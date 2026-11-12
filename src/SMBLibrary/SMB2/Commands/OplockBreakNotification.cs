/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 OPLOCK_BREAK Notification, [MS-SMB2] 2.2.23.1
    /// </summary>
    internal class OplockBreakNotification : SMB2Command
    {
        public const int DeclaredSize = 24;

        private ushort StructureSize;
        public byte OplockLevel;
        public byte Reserved;
        public uint Reserved2;
        public FileID FileId;

        public OplockBreakNotification(byte[] buffer, int offset) : base(buffer, offset)
        {
            int dataOffset = offset + SMB2Header.Length;
            StructureSize = LittleEndianConverter.ToUInt16(buffer, dataOffset + 0);
            OplockLevel = ByteReader.ReadByte(buffer, dataOffset + 2);
            Reserved = ByteReader.ReadByte(buffer, dataOffset + 3);
            Reserved2 = LittleEndianConverter.ToUInt32(buffer, dataOffset + 4);
            FileId = new FileID(buffer, dataOffset + 8);
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            throw new NotSupportedException();
        }

        public override int CommandLength
        {
            get
            {
                return DeclaredSize;
            }
        }
    }
}
