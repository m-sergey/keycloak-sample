package me.keycloak.util;

import org.keycloak.common.ClientConnection;

public class SimpleClientConnection implements ClientConnection {

    private final String remoteAddr = "0.0.0.0";
    private final String remoteHost = "localhost.local";


    @Override
    public String getRemoteAddr() {
        return remoteAddr;
    }

    @Override
    public String getRemoteHost() {
        return remoteHost;
    }

    @Override
    public int getRemotePort() {
        return 0;
    }

    @Override
    public String getLocalAddr() {
        return remoteAddr;
    }

    @Override
    public int getLocalPort() {
        return 0;
    }
}
