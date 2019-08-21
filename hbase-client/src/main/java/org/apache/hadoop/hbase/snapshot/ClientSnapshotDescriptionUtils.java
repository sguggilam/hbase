/**
 *
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
package org.apache.hadoop.hbase.snapshot;

import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.classification.InterfaceAudience;
import org.apache.hadoop.hbase.protobuf.generated.HBaseProtos.SnapshotDescription;
import org.apache.hadoop.hbase.util.Bytes;

/**
 * Class to help with dealing with a snapshot description on the client side.
 * There is a corresponding class on the server side.
 */
@InterfaceAudience.Private
public final class ClientSnapshotDescriptionUtils {
  private ClientSnapshotDescriptionUtils() {
  }

  /**
   * Check to make sure that the description of the snapshot requested is valid
   * @param snapshot description of the snapshot
   * @throws IllegalArgumentException if the name of the snapshot or the name of the table to
   *           snapshot are not valid names
   */
  public static void assertSnapshotRequestIsValid(SnapshotDescription snapshot)
      throws IllegalArgumentException {
    // make sure the snapshot name is valid
    TableName.isLegalTableQualifierName(Bytes.toBytes(snapshot.getName()), true);
    if (snapshot.hasTable()) {
      // make sure the table name is valid, this will implicitly check validity
      TableName tableName = TableName.valueOf(snapshot.getTable());

      if (tableName.isSystemTable()) {
        throw new IllegalArgumentException("System table snapshots are not allowed");
      }
    }
  }

  /**
   * Returns a single line (no \n) representation of snapshot metadata. Use this instead of
   * {@link org.apache.hadoop.hbase.protobuf.generated.HBaseProtos.SnapshotDescription#toString()}.
   * We don't replace
   * {@link org.apache.hadoop.hbase.protobuf.generated.HBaseProtos.SnapshotDescription}'s
   * {@code toString}, because it is auto-generated by protoc.
   *
   * @param snapshot description of the snapshot
   * @return single line string with a summary of the snapshot parameters
   */
  public static String toString(SnapshotDescription snapshot) {
    if (snapshot == null) {
      return null;
    }

    return new StringBuilder("{ ss=")
            .append(snapshot.getName())
            .append(" table=")
            .append(snapshot.hasTable() ? TableName.valueOf(snapshot.getTable()) : "")
            .append(" type=")
            .append(snapshot.getType())
            .append(" ttl=")
            .append(snapshot.getTtl())
            .append(" }")
            .toString();
  }
}
