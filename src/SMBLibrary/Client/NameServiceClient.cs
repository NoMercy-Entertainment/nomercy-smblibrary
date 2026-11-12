/* Copyright (C) 2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using SMBLibrary.NetBios;

namespace SMBLibrary.Client
{
    public class NameServiceClient
    {
        public static readonly int NetBiosNameServicePort = 137;

        private const int DefaultReceiveTimeout = 5000;

        private IPAddress m_serverAddress;
        private int m_port;
        private int m_receiveTimeout;

        public NameServiceClient(IPAddress serverAddress) : this(serverAddress, NetBiosNameServicePort, DefaultReceiveTimeout)
        {
        }

        internal NameServiceClient(IPAddress serverAddress, int port, int receiveTimeout)
        {
            m_serverAddress = serverAddress;
            m_port = port;
            m_receiveTimeout = receiveTimeout;
        }

        public string GetServerName()
        {
            NodeStatusRequest request = new NodeStatusRequest();
            request.Header.QDCount = 1;
            request.Question.Name = "*".PadRight(16, '\0');
            NodeStatusResponse response = SendNodeStatusRequest(request);
            if (response == null)
            {
                return null;
            }
            foreach (KeyValuePair<string, NameFlags> entry in response.Names)
            {
                NetBiosSuffix suffix = NetBiosUtils.GetSuffixFromMSNetBiosName(entry.Key);
                if (suffix == NetBiosSuffix.FileServerService)
                {
                    return entry.Key;
                }
            }

            return null;
        }

        private NodeStatusResponse SendNodeStatusRequest(NodeStatusRequest request)
        {
            using (UdpClient client = new UdpClient())
            {
                client.Client.ReceiveTimeout = m_receiveTimeout;
                IPEndPoint serverEndPoint = new IPEndPoint(m_serverAddress, m_port);
                client.Connect(serverEndPoint);

                byte[] requestBytes = request.GetBytes();
                client.Send(requestBytes, requestBytes.Length);
                try
                {
                    byte[] responseBytes = client.Receive(ref serverEndPoint);
                    return new NodeStatusResponse(responseBytes, 0);
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                {
                    return null;
                }
            }
        }
    }
}
