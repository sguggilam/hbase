/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hbase.master.procedure;

import static org.apache.hadoop.hbase.HConstants.DEFAULT_HBASE_SPLIT_COORDINATED_BY_ZK;
import static org.apache.hadoop.hbase.HConstants.HBASE_SPLIT_WAL_COORDINATED_BY_ZK;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.hadoop.hbase.DoNotRetryIOException;
import org.apache.hadoop.hbase.ServerName;
import org.apache.hadoop.hbase.client.RegionInfo;
import org.apache.hadoop.hbase.client.RegionInfoBuilder;
import org.apache.hadoop.hbase.client.RegionReplicaUtil;
import org.apache.hadoop.hbase.client.TableState;
import org.apache.hadoop.hbase.master.MasterServices;
import org.apache.hadoop.hbase.master.MasterWalManager;
import org.apache.hadoop.hbase.master.SplitWALManager;
import org.apache.hadoop.hbase.master.assignment.AssignmentManager;
import org.apache.hadoop.hbase.master.assignment.RegionStateNode;
import org.apache.hadoop.hbase.master.assignment.TransitRegionStateProcedure;
import org.apache.hadoop.hbase.monitoring.MonitoredTask;
import org.apache.hadoop.hbase.monitoring.TaskMonitor;
import org.apache.hadoop.hbase.procedure2.Procedure;
import org.apache.hadoop.hbase.procedure2.ProcedureMetrics;
import org.apache.hadoop.hbase.procedure2.ProcedureStateSerializer;
import org.apache.hadoop.hbase.procedure2.ProcedureSuspendedException;
import org.apache.hadoop.hbase.procedure2.ProcedureYieldException;
import org.apache.hadoop.hbase.procedure2.StateMachineProcedure;
import org.apache.yetus.audience.InterfaceAudience;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.hbase.shaded.protobuf.ProtobufUtil;
import org.apache.hadoop.hbase.shaded.protobuf.generated.MasterProcedureProtos;
import org.apache.hadoop.hbase.shaded.protobuf.generated.MasterProcedureProtos.ServerCrashState;

/**
 * Handle crashed server. This is a port to ProcedureV2 of what used to be euphemistically called
 * ServerShutdownHandler.
 *
 * <p>The procedure flow varies dependent on whether meta is assigned and if we are to split logs.
 *
 * <p>We come in here after ServerManager has noticed a server has expired. Procedures
 * queued on the rpc should have been notified about fail and should be concurrently
 * getting themselves ready to assign elsewhere.
 */
@InterfaceAudience.Private
public class ServerCrashProcedure
    extends StateMachineProcedure<MasterProcedureEnv, ServerCrashState>
    implements ServerProcedureInterface {
  private static final Logger LOG = LoggerFactory.getLogger(ServerCrashProcedure.class);

  /**
   * Name of the crashed server to process.
   */
  private ServerName serverName;

  /**
   * Whether DeadServer knows that we are processing it.
   */
  private boolean notifiedDeadServer = false;

  /**
   * Regions that were on the crashed server.
   */
  private List<RegionInfo> regionsOnCrashedServer;

  private boolean carryingRoot = false;
  private boolean carryingMeta = false;
  private boolean shouldSplitWal;
  private MonitoredTask status;
  // currentRunningState is updated when ServerCrashProcedure get scheduled, child procedures update
  // progress will not update the state because the actual state is overwritten by its next state
  private ServerCrashState currentRunningState = getInitialState();

  /**
   * Call this constructor queuing up a Procedure.
   * @param serverName Name of the crashed server.
   * @param shouldSplitWal True if we should split WALs as part of crashed server processing.
   * @param carryingRoot True if carrying hbase:root table region.
   * @param carryingMeta True if carrying hbase:meta table region. Although carryingMeta is
   *                     determined dynamically by an SCP instance. Caller can give the current
   *                     state it sees, this information might be useful to SCP down the road or
   *                     for debugging.
   */
  public ServerCrashProcedure(final MasterProcedureEnv env, final ServerName serverName,
      final boolean shouldSplitWal, final boolean carryingRoot, final boolean carryingMeta) {
    this.serverName = serverName;
    this.shouldSplitWal = shouldSplitWal;
    this.carryingRoot = carryingRoot;
    this.carryingMeta = carryingMeta;
    this.setOwner(env.getRequestUser());
  }

  /**
   * Used when deserializing from a procedure store; we'll construct one of these then call
   * #deserializeStateData(InputStream). Do not use directly.
   */
  public ServerCrashProcedure() {
  }

  public boolean isInRecoverMetaState() {
    return getCurrentState() == ServerCrashState.SERVER_CRASH_PROCESS_META;
  }

  @Override
  protected Flow executeFromState(MasterProcedureEnv env, ServerCrashState state)
      throws ProcedureSuspendedException, ProcedureYieldException {
    final MasterServices services = env.getMasterServices();
    final AssignmentManager am = env.getAssignmentManager();
    updateProgress(true);
    // HBASE-14802 If we have not yet notified that we are processing a dead server, do so now.
    // This adds server to the DeadServer processing list but not to the DeadServers list.
    // Server gets removed from processing list below on procedure successful finish.
    if (!notifiedDeadServer) {
      services.getServerManager().getDeadServers().processing(serverName);
      notifiedDeadServer = true;
    }

    switch (state) {
      case SERVER_CRASH_START:
        break;

      //Don't block hbase:root processing states on hbase:meta being loaded
      case SERVER_CRASH_SPLIT_ROOT_LOGS:
      case SERVER_CRASH_DELETE_SPLIT_ROOT_WALS_DIR:
      case SERVER_CRASH_ASSIGN_ROOT:
        break;

      //Don't block hbase:meta processing states on hbase:meta being loaded
      case SERVER_CRASH_CHECK_CARRYING_META:
      case SERVER_CRASH_SPLIT_META_LOGS:
      case SERVER_CRASH_DELETE_SPLIT_META_WALS_DIR:
      case SERVER_CRASH_ASSIGN_META:
        // If hbase:root is not loaded, we can't do the check so yield
        if (env.getAssignmentManager().waitRootLoaded(this)) {
          LOG.info("pid="+getProcId()+", waiting for root loaded: "+state+
            ", carryingRoot="+carryingRoot+", carryingMeta="+carryingMeta);
          throw new ProcedureSuspendedException();
        }
        break;

      default:
        // If hbase:meta is not assigned, yield.
        if (env.getAssignmentManager().waitMetaLoaded(this)) {
          LOG.info("pid="+getProcId()+", waiting for meta loaded: "+state+
            ", carryingRoot="+carryingRoot+", carryingMeta="+carryingMeta);
          throw new ProcedureSuspendedException();
        }
    }

    try {
      switch (state) {
        case SERVER_CRASH_START:
          LOG.info("Start " + this);
          // If carrying meta, process it first. Else, get list of regions on crashed server.
          if (this.carryingRoot) {
            setNextState(ServerCrashState.SERVER_CRASH_SPLIT_ROOT_LOGS);
          } else  {
            setNextState(ServerCrashState.SERVER_CRASH_CHECK_CARRYING_META);
          }
          break;
        case SERVER_CRASH_SPLIT_ROOT_LOGS:
          if (env.getMasterConfiguration().getBoolean(HBASE_SPLIT_WAL_COORDINATED_BY_ZK,
            DEFAULT_HBASE_SPLIT_COORDINATED_BY_ZK)) {
            splitRootLogs(env);
            setNextState(ServerCrashState.SERVER_CRASH_ASSIGN_ROOT);
          } else {
            am.getRegionStates().rootLogSplitting(serverName);
            addChildProcedure(createSplittingWalProcedures(env, SplitWALManager.SplitType.ROOT));
            setNextState(ServerCrashState.SERVER_CRASH_DELETE_SPLIT_ROOT_WALS_DIR);
          }
          break;
        case SERVER_CRASH_DELETE_SPLIT_ROOT_WALS_DIR:
          if(isSplittingDone(env, SplitWALManager.SplitType.ROOT)){
            //TODO francis are we cleaning all the dirs?
            cleanupSplitDir(env);
            setNextState(ServerCrashState.SERVER_CRASH_ASSIGN_ROOT);
            am.getRegionStates().rootLogSplit(serverName);
          } else {
            setNextState(ServerCrashState.SERVER_CRASH_SPLIT_ROOT_LOGS);
          }
          break;
        case SERVER_CRASH_ASSIGN_ROOT:
          assignRegions(env, Arrays.asList(RegionInfoBuilder.ROOT_REGIONINFO));
          setNextState(ServerCrashState.SERVER_CRASH_CHECK_CARRYING_META);
          break;
        case SERVER_CRASH_CHECK_CARRYING_META:
          boolean currCarryingMeta = am.isCarryingMeta(serverName);
          if (carryingMeta && !currCarryingMeta) {
            LOG.error("pid="+getProcId()+", carryingMeta changed to false after SCP check");
          }
          carryingMeta = currCarryingMeta;
          if (carryingMeta) {
            setNextState(ServerCrashState.SERVER_CRASH_SPLIT_META_LOGS);
          } else {
            setNextState(ServerCrashState.SERVER_CRASH_GET_REGIONS);
          }
          break;
        case SERVER_CRASH_SPLIT_META_LOGS:
          if (env.getMasterConfiguration().getBoolean(HBASE_SPLIT_WAL_COORDINATED_BY_ZK,
            DEFAULT_HBASE_SPLIT_COORDINATED_BY_ZK)) {
            splitMetaLogs(env);
            setNextState(ServerCrashState.SERVER_CRASH_ASSIGN_META);
          } else {
            am.getRegionStates().metaLogSplitting(serverName);
            addChildProcedure(createSplittingWalProcedures(env, SplitWALManager.SplitType.META));
            setNextState(ServerCrashState.SERVER_CRASH_DELETE_SPLIT_META_WALS_DIR);
          }
          break;
        case SERVER_CRASH_DELETE_SPLIT_META_WALS_DIR:
          if (isSplittingDone(env, SplitWALManager.SplitType.META)) {
            setNextState(ServerCrashState.SERVER_CRASH_ASSIGN_META);
            am.getRegionStates().metaLogSplit(serverName);
          } else {
            setNextState(ServerCrashState.SERVER_CRASH_SPLIT_META_LOGS);
          }
          break;
        case SERVER_CRASH_ASSIGN_META:
          assignRegions(env, Arrays.asList(RegionInfoBuilder.FIRST_META_REGIONINFO));
          setNextState(ServerCrashState.SERVER_CRASH_GET_REGIONS);
          break;
        case SERVER_CRASH_GET_REGIONS:
          this.regionsOnCrashedServer = getRegionsOnCrashedServer(env);
          // Where to go next? Depends on whether we should split logs at all or
          // if we should do distributed log splitting.
          if (regionsOnCrashedServer != null) {
            LOG.info("{} had {} regions", serverName, regionsOnCrashedServer.size());
            if (LOG.isTraceEnabled()) {
              this.regionsOnCrashedServer.stream().forEach(ri -> LOG.trace(ri.getShortNameToLog()));
            }
          }
          if (!this.shouldSplitWal) {
            setNextState(ServerCrashState.SERVER_CRASH_ASSIGN);
          } else {
            setNextState(ServerCrashState.SERVER_CRASH_SPLIT_LOGS);
          }
          break;
        case SERVER_CRASH_SPLIT_LOGS:
          if (env.getMasterConfiguration().getBoolean(HBASE_SPLIT_WAL_COORDINATED_BY_ZK,
            DEFAULT_HBASE_SPLIT_COORDINATED_BY_ZK)) {
            splitLogs(env);
            setNextState(ServerCrashState.SERVER_CRASH_ASSIGN);
          } else {
            am.getRegionStates().logSplitting(this.serverName);
            addChildProcedure(createSplittingWalProcedures(env, SplitWALManager.SplitType.USER));
            setNextState(ServerCrashState.SERVER_CRASH_DELETE_SPLIT_WALS_DIR);
          }
          break;
        case SERVER_CRASH_DELETE_SPLIT_WALS_DIR:
          if (isSplittingDone(env, SplitWALManager.SplitType.USER)) {
            cleanupSplitDir(env);
            setNextState(ServerCrashState.SERVER_CRASH_ASSIGN);
            am.getRegionStates().logSplit(this.serverName);
          } else {
            setNextState(ServerCrashState.SERVER_CRASH_SPLIT_LOGS);
          }
          break;
        case SERVER_CRASH_ASSIGN:
          // If no regions to assign, skip assign and skip to the finish.
          // Filter out meta regions. Those are handled elsewhere in this procedure.
          // Filter changes this.regionsOnCrashedServer.
          if (filterDefaultMetaRegions()) {
            if (LOG.isTraceEnabled()) {
              LOG
                .trace("Assigning regions " + RegionInfo.getShortNameToLog(regionsOnCrashedServer) +
                  ", " + this + "; cycles=" + getCycles());
            }
            assignRegions(env, regionsOnCrashedServer);
          }
          setNextState(ServerCrashState.SERVER_CRASH_FINISH);
          break;
        case SERVER_CRASH_HANDLE_RIT2:
          // Noop. Left in place because we used to call handleRIT here for a second time
          // but no longer necessary since HBASE-20634.
          setNextState(ServerCrashState.SERVER_CRASH_FINISH);
          break;
        case SERVER_CRASH_FINISH:
          LOG.info("removed crashed server {} after splitting done", serverName);
          services.getAssignmentManager().getRegionStates().removeServer(serverName);
          services.getServerManager().getDeadServers().finish(serverName);
          updateProgress(true);
          return Flow.NO_MORE_STATE;
        default:
          throw new UnsupportedOperationException("unhandled state=" + state);
      }
    } catch (IOException e) {
      LOG.warn("Failed state=" + state + ", retry " + this + "; cycles=" + getCycles(), e);
    }
    return Flow.HAS_MORE_STATE;
  }

  /**
   * @return List of Regions on crashed server.
   */
  List<RegionInfo> getRegionsOnCrashedServer(MasterProcedureEnv env) {
    return env.getMasterServices().getAssignmentManager().getRegionsOnServer(serverName);
  }

  private void cleanupSplitDir(MasterProcedureEnv env) {
    SplitWALManager splitWALManager = env.getMasterServices().getSplitWALManager();
    try {
      splitWALManager.deleteWALDir(serverName);
    } catch (IOException e) {
      LOG.warn("Remove WAL directory of server {} failed, ignore...", serverName, e);
    }
  }

  private boolean isSplittingDone(MasterProcedureEnv env, SplitWALManager.SplitType splitType) {
    LOG.debug("check if splitting WALs of {} done? splittype: {}", serverName, splitType);
    SplitWALManager splitWALManager = env.getMasterServices().getSplitWALManager();
    try {
      return splitWALManager.getWALsToSplit(serverName, splitType).size() == 0;
    } catch (IOException e) {
      LOG.warn("get filelist of serverName {} failed, retry...", serverName, e);
      return false;
    }
  }

  private Procedure[] createSplittingWalProcedures(MasterProcedureEnv env,
    SplitWALManager.SplitType splitType)
      throws IOException {
    LOG.info("Splitting WALs {}, SplitType: {}", this, splitType);
    SplitWALManager splitWALManager = env.getMasterServices().getSplitWALManager();
    List<Procedure> procedures = splitWALManager.splitWALs(serverName, splitType);
    return procedures.toArray(new Procedure[procedures.size()]);
  }

  private boolean filterDefaultMetaRegions() {
    if (regionsOnCrashedServer == null) {
      return false;
    }
    regionsOnCrashedServer.removeIf((x) -> isDefaultMetaRegion(x) || isDefaultRootRegion(x));
    return !regionsOnCrashedServer.isEmpty();
  }

  private boolean isDefaultRootRegion(RegionInfo hri) {
    return hri.isRootRegion() && RegionReplicaUtil.isDefaultReplica(hri);
  }

  private boolean isDefaultMetaRegion(RegionInfo hri) {
    return hri.isMetaRegion() && RegionReplicaUtil.isDefaultReplica(hri);
  }

  private void splitRootLogs(MasterProcedureEnv env) throws IOException {
    LOG.debug("Splitting root WALs {}", this);
    MasterWalManager mwm = env.getMasterServices().getMasterWalManager();
    AssignmentManager am = env.getMasterServices().getAssignmentManager();
    am.getRegionStates().rootLogSplitting(serverName);
    mwm.splitRootLog(serverName);
    am.getRegionStates().rootLogSplit(serverName);
    LOG.debug("Done splitting root WALs {}", this);
  }

  private void splitMetaLogs(MasterProcedureEnv env) throws IOException {
    LOG.debug("Splitting meta WALs {}", this);
    MasterWalManager mwm = env.getMasterServices().getMasterWalManager();
    AssignmentManager am = env.getMasterServices().getAssignmentManager();
    am.getRegionStates().metaLogSplitting(serverName);
    mwm.splitMetaLog(serverName);
    am.getRegionStates().metaLogSplit(serverName);
    LOG.debug("Done splitting meta WALs {}", this);
  }

  private void splitLogs(final MasterProcedureEnv env) throws IOException {
    LOG.debug("Splitting WALs {}", this);
    MasterWalManager mwm = env.getMasterServices().getMasterWalManager();
    AssignmentManager am = env.getMasterServices().getAssignmentManager();
    // TODO: For Matteo. Below BLOCKs!!!! Redo so can relinquish executor while it is running.
    // PROBLEM!!! WE BLOCK HERE. Can block for hours if hundreds of WALs to split and hundreds
    // of SCPs running because big cluster crashed down.
    am.getRegionStates().logSplitting(this.serverName);
    mwm.splitLog(this.serverName);
    if (!carryingRoot) {
      mwm.archiveCatalogLog(this.serverName, true);
    }
    if (!carryingMeta) {
      mwm.archiveCatalogLog(this.serverName, false);
    }
    am.getRegionStates().logSplit(this.serverName);
    LOG.debug("Done splitting WALs {}", this);
  }

  void updateProgress(boolean updateState) {
    String msg = "Processing ServerCrashProcedure of " + serverName;
    if (status == null) {
      status = TaskMonitor.get().createStatus(msg);
      return;
    }
    if (currentRunningState == ServerCrashState.SERVER_CRASH_FINISH) {
      status.markComplete(msg + " done");
      return;
    }
    if (updateState) {
      currentRunningState = getCurrentState();
    }
    int childrenLatch = getChildrenLatch();
    status.setStatus(msg + " current State " + currentRunningState
        + (childrenLatch > 0 ? "; remaining num of running child procedures = " + childrenLatch
            : ""));
  }

  @Override
  protected void rollbackState(MasterProcedureEnv env, ServerCrashState state)
  throws IOException {
    // Can't rollback.
    throw new UnsupportedOperationException("unhandled state=" + state);
  }

  @Override
  protected ServerCrashState getState(int stateId) {
    return ServerCrashState.forNumber(stateId);
  }

  @Override
  protected int getStateId(ServerCrashState state) {
    return state.getNumber();
  }

  @Override
  protected ServerCrashState getInitialState() {
    return ServerCrashState.SERVER_CRASH_START;
  }

  @Override
  protected boolean abort(MasterProcedureEnv env) {
    // TODO
    return false;
  }

  @Override
  protected LockState acquireLock(final MasterProcedureEnv env) {
    if (env.getProcedureScheduler().waitServerExclusiveLock(this, getServerName())) {
      return LockState.LOCK_EVENT_WAIT;
    }
    return LockState.LOCK_ACQUIRED;
  }

  @Override
  protected void releaseLock(final MasterProcedureEnv env) {
    env.getProcedureScheduler().wakeServerExclusiveLock(this, getServerName());
  }

  @Override
  public void toStringClassDetails(StringBuilder sb) {
    sb.append(getProcName());
    sb.append(", splitWal=");
    sb.append(shouldSplitWal);
    sb.append(", root=");
    sb.append(carryingRoot);
    sb.append(", meta=");
    sb.append(carryingMeta);
  }

  @Override public String getProcName() {
    return getClass().getSimpleName() + " " + this.serverName;
  }

  @Override
  protected void serializeStateData(ProcedureStateSerializer serializer)
      throws IOException {
    super.serializeStateData(serializer);

    MasterProcedureProtos.ServerCrashStateData.Builder state =
      MasterProcedureProtos.ServerCrashStateData.newBuilder().
      setServerName(ProtobufUtil.toServerName(this.serverName)).
      setCarryingRoot(this.carryingRoot).
      setCarryingMeta(this.carryingMeta).
      setShouldSplitWal(this.shouldSplitWal);
    if (this.regionsOnCrashedServer != null && !this.regionsOnCrashedServer.isEmpty()) {
      for (RegionInfo hri: this.regionsOnCrashedServer) {
        state.addRegionsOnCrashedServer(ProtobufUtil.toRegionInfo(hri));
      }
    }
    serializer.serialize(state.build());
  }

  @Override
  protected void deserializeStateData(ProcedureStateSerializer serializer)
      throws IOException {
    super.deserializeStateData(serializer);

    MasterProcedureProtos.ServerCrashStateData state =
        serializer.deserialize(MasterProcedureProtos.ServerCrashStateData.class);
    this.serverName = ProtobufUtil.toServerName(state.getServerName());
    this.carryingRoot = state.hasCarryingRoot()? state.getCarryingRoot(): false;
    this.carryingMeta = state.hasCarryingMeta()? state.getCarryingMeta(): false;
    // shouldSplitWAL has a default over in pb so this invocation will always work.
    this.shouldSplitWal = state.getShouldSplitWal();
    int size = state.getRegionsOnCrashedServerCount();
    if (size > 0) {
      this.regionsOnCrashedServer = new ArrayList<>(size);
      for (org.apache.hadoop.hbase.shaded.protobuf.generated.HBaseProtos.RegionInfo ri: state.getRegionsOnCrashedServerList()) {
        this.regionsOnCrashedServer.add(ProtobufUtil.toRegionInfo(ri));
      }
    }
    updateProgress(false);
  }

  @Override
  public ServerName getServerName() {
    return this.serverName;
  }

  @Override
  public boolean hasRootTableRegion() {
    return this.carryingRoot;
  }

  @Override
  public boolean hasMetaTableRegion() {
    return this.carryingMeta;
  }

  @Override
  public ServerOperationType getServerOperationType() {
    return ServerOperationType.CRASH_HANDLER;
  }


  @Override
  protected boolean shouldWaitClientAck(MasterProcedureEnv env) {
    // The operation is triggered internally on the server
    // the client does not know about this procedure.
    return false;
  }

  /**
   * Moved out here so can be overridden by the HBCK fix-up SCP to be less strict about what
   * it will tolerate as a 'match'.
   * @return True if the region location in <code>rsn</code> matches that of this crashed server.
   */
  protected boolean isMatchingRegionLocation(RegionStateNode rsn) {
    return this.serverName.equals(rsn.getRegionLocation());
  }

  /**
   * Assign the regions on the crashed RS to other Rses.
   * <p/>
   * In this method we will go through all the RegionStateNodes of the give regions to find out
   * whether there is already an TRSP for the region, if so we interrupt it and let it retry on
   * other server, otherwise we will schedule a TRSP to bring the region online.
   * <p/>
   * We will also check whether the table for a region is enabled, if not, we will skip assigning
   * it.
   */
  private void assignRegions(MasterProcedureEnv env, List<RegionInfo> regions) throws IOException {
    AssignmentManager am = env.getMasterServices().getAssignmentManager();
    for (RegionInfo region : regions) {
      RegionStateNode regionNode = am.getRegionStates().getOrCreateRegionStateNode(region);
      regionNode.lock();
      try {
        // This is possible, as when a server is dead, TRSP will fail to schedule a RemoteProcedure
        // and then try to assign the region to a new RS. And before it has updated the region
        // location to the new RS, we may have already called the am.getRegionsOnServer so we will
        // consider the region is still on this crashed server. Then before we arrive here, the
        // TRSP could have updated the region location, or even finished itself, so the region is
        // no longer on this crashed server any more. We should not try to assign it again. Please
        // see HBASE-23594 for more details.
        // UPDATE: HBCKServerCrashProcedure overrides isMatchingRegionLocation; this check can get
        // in the way of our clearing out 'Unknown Servers'.
        if (!isMatchingRegionLocation(regionNode)) {
          // See HBASE-24117, though we have already changed the shutdown order, it is still worth
          // double checking here to confirm that we do not skip assignment incorrectly.
          if (!am.isRunning()) {
            throw new DoNotRetryIOException(
              "AssignmentManager has been stopped, can not process assignment any more");
          }
          LOG.info("{} found {} whose regionLocation no longer matches {}, skipping assign...",
            this, regionNode, serverName);
          continue;
        }
        if (regionNode.getProcedure() != null) {
          LOG.info("{} found RIT {}; {}", this, regionNode.getProcedure(), regionNode);
          regionNode.getProcedure().serverCrashed(env, regionNode, getServerName());
          continue;
        }
        if (env.getMasterServices().getTableStateManager()
          .isTableState(regionNode.getTable(), TableState.State.DISABLING)) {
          // We need to change the state here otherwise the TRSP scheduled by DTP will try to
          // close the region from a dead server and will never succeed. Please see HBASE-23636
          // for more details.
          env.getAssignmentManager().regionClosedAbnormally(regionNode);
          LOG.info("{} found table disabling for region {}, set it state to ABNORMALLY_CLOSED.",
            this, regionNode);
          continue;
        }
        if (env.getMasterServices().getTableStateManager()
          .isTableState(regionNode.getTable(), TableState.State.DISABLED)) {
          // This should not happen, table disabled but has regions on server.
          LOG.warn("Found table disabled for region {}, procDetails: {}", regionNode, this);
          continue;
        }
        // force to assign to a new candidate server, see HBASE-23035 for more details.
        TransitRegionStateProcedure proc =
          TransitRegionStateProcedure.assign(env, region, true, null);
        regionNode.setProcedure(proc);
        addChildProcedure(proc);
      } finally {
        regionNode.unlock();
      }
    }
  }

  @Override
  protected ProcedureMetrics getProcedureMetrics(MasterProcedureEnv env) {
    return env.getMasterServices().getMasterMetrics().getServerCrashProcMetrics();
  }

  @Override
  protected boolean holdLock(MasterProcedureEnv env) {
    return true;
  }

  public static void updateProgress(MasterProcedureEnv env, long parentId) {
    if (parentId == NO_PROC_ID) {
      return;
    }
    Procedure parentProcedure =
        env.getMasterServices().getMasterProcedureExecutor().getProcedure(parentId);
    if (parentProcedure != null && parentProcedure instanceof ServerCrashProcedure) {
      ((ServerCrashProcedure) parentProcedure).updateProgress(false);
    }
  }
}
