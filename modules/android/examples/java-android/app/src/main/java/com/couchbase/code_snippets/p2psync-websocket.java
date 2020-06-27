// PASSIVE PEER STUFF
// Stuff I adapted
//


import Foundation
import CouchbaseLiteSwift
import MultipeerConnectivity

class cMyPassListener {
  // // tag::listener-initialize[]
  // fileprivate var _allowlistedUsers:[[String:String]] = []
  // fileprivate var _websocketListener:URLEndpointListener?
  // fileprivate var _userDb:Database?
    // Include websockets listener initializer code

    // func fMyPassListener() {
    // tag::listener-config-endpoint[]
    CouchbaseLite.init(context);
    Database passDb = new Database("passivepeerdb");  // <.>
    URLEndpointListenerConfiguration listenerConfig = new URLEndpointListenerConfiguration(passDB);
    // tag::listener-config-port[]
    /* optionally */ Integer wsPort = 4984;
    /* optionally */ Integer wssPort = 4985;
    listenerConfig.setPort(wssPort);
    // end::listener-config-port[]

    // tag::listener-config-netw-iface[]
    listenerConfig.setNetworkInterface = "10.1.1.10";
    // end::listener-config-netw-iface[]
    // end::listener-config-endpoint[]

    // tag::listener-config-tls-full[]
    // This combination will set
    // tag::listener-config-tls-enable[]
    // -- TLS on
    //    optionally switch it off .disableTLS  = true
    listenerConfig.setDisableTLS  = false; // <.>
    // end::listener-config-tls-enable[]
    // tag::listener-config-tls-id-full[]
    // tag::listener-config-tls-id-nil[]
    // -- Use anonymous self-cert
    listenerConfig.tlsIdentity = nil;
    // end::listener-config-tls-id-nil[]
    // tag::listener-config-tls-id-cert[]
    // -- Use id and certs from keychain
    listenerConfig.tlsIdentity = TLSIdentity("CBL-Android-Server-Cert");
    // optionally  listenerConfig.tlsIdentity = TLSIdentity(withIdentity:serverSelfCert-id)
    // end::listener-config-tls-id-cert[]
    // end::listener-config-tls-id-full[]

    // tag::listener-config-auth[]
    listenerConfig.authenticator = ListenerPasswordAuthenticator.init { // <.>
        (username, password) -> Bool in
            if (self._allowlistedUsers.contains(
              ["password" : password, "name":username])) {
                return true
            }
        return false
    };
    // end::listener-config-auth[]

    listenerConfig.enableDeltaSync = true; // <.>

    // tag::listener-start[]
    URLEndpointListener websocketListener = new URLEndpointListener(config: listenerConfig); // <.>

    // websocketListener = _websocketListener else {
    //   throw print("WebsocketsListenerNotInitialized")
    //   // ... take appropriate actions
    // }
    try websocketListener.start() // <.> <.>
    // end::listener-start[]
// end::listener-initialize[]

  }
}


// tag::listener-config-tls-disable[]
listenerConfig.disableTLS  = true
// end::listener-config-tls-disable[]

// tag::listener-config-tls-id-nil[]
listenerConfig.tlsIdentity = nil
// end::listener-config-tls-id-nil[]


// tag::listener-config-delta-sync[]
listenerConfig.enableDeltaSync = true
// end::listener-config-delta-sync[]


// tag::listener-status-check[]
var totalConnections = websocketListener.status.connectionCount
var activeConnections = websocketListener.status.activeConnectionCount
// end::listener-status-check[]


// tag::listener-stop[]
websocketListener.stop()
// end::listener-stop[]

// tag::listener-config-client-auth-root[]
  // cert is a pre-populated object of type:SecCertificate representing a certificate
  let rootCertData = SecCertificateCopyData(cert) as Data
  let rootCert = SecCertificateCreateWithData(kCFAllocatorDefault, rootCertData as CFData)!
  // Listener:
  listenerConfig.authenticator = ListenerCertificateAuthenticator.init (rootCerts: [rootCert])
// end::listener-config-client-auth-root[]


// tag::listener-config-client-auth-self-signed[]
listenerConfig.authenticator = ListenerCertificateAuthenticator.init {
  (cert) -> Bool in
    var cert:SecCertificate
    var certCommonName:CFString?
    let status=SecCertificateCopyCommonName(cert, &certCommonName)
    if (self._allowlistedUsers.contains(["name": certCommonName! as String])) {
        return true
    }
    return false
}
// end::listener-config-client-auth-self-signed[]

// tag::p2p-ws-api-urlendpointlistener[]
public class URLEndpointListener {
    // Properties // <1>
    public let config: URLEndpointListenerConfiguration
    public let port UInt16?
    public let tlsIdentity: TLSIdentity?
    public let urls: Array<URL>?
    public let status: ConnectionStatus?
    // Constructors <2>
    public init(config: URLEndpointListenerConfiguration)
    // Methods <3>
    public func start() throws
    public func stop()
}
// end::p2p-ws-api-urlendpointlistener[]


// tag::p2p-ws-api-urlendpointlistener-constructor[]
let config = URLEndpointListenerConfiguration.init(database: self.oDB)
config.port = tls ? wssPort : wsPort
config.disableTLS = !tls
config.authenticator = auth
self.listener = URLEndpointListener.init(config: config) // <1>
// end::p2p-ws-api-urlendpointlistener-constructor[]


// ACTIVE PEER STUFF
// Replication code
//
// Copyright (c) 2019 Couchbase, Inc All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package com.couchbase.code_snippets;

import android.content.Context;
import android.support.annotation.NonNull;
import android.util.Log;
import android.widget.Toast;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import com.couchbase.lite.ArrayFunction;
import com.couchbase.lite.BasicAuthenticator;
import com.couchbase.lite.Blob;
import com.couchbase.lite.Conflict;
import com.couchbase.lite.ConflictResolver;
import com.couchbase.lite.CouchbaseLite;
import com.couchbase.lite.CouchbaseLiteException;
import com.couchbase.lite.DataSource;
import com.couchbase.lite.Database;
import com.couchbase.lite.DatabaseConfiguration;
import com.couchbase.lite.DatabaseEndpoint;
import com.couchbase.lite.Dictionary;
import com.couchbase.lite.Document;
import com.couchbase.lite.DocumentFlag;
import com.couchbase.lite.EncryptionKey;
import com.couchbase.lite.Endpoint;
import com.couchbase.lite.Expression;
import com.couchbase.lite.FullTextExpression;
import com.couchbase.lite.FullTextIndexItem;
import com.couchbase.lite.Function;
import com.couchbase.lite.IndexBuilder;
import com.couchbase.lite.Join;
import com.couchbase.lite.ListenerToken;
import com.couchbase.lite.LogDomain;
import com.couchbase.lite.LogFileConfiguration;
import com.couchbase.lite.LogLevel;
import com.couchbase.lite.Logger;
import com.couchbase.lite.Message;
import com.couchbase.lite.MessageEndpoint;
import com.couchbase.lite.MessageEndpointConnection;
import com.couchbase.lite.MessageEndpointDelegate;
import com.couchbase.lite.MessageEndpointListener;
import com.couchbase.lite.MessageEndpointListenerConfiguration;
import com.couchbase.lite.MessagingCloseCompletion;
import com.couchbase.lite.MessagingCompletion;
import com.couchbase.lite.Meta;
import com.couchbase.lite.MutableDictionary;
import com.couchbase.lite.MutableDocument;
import com.couchbase.lite.Ordering;
import com.couchbase.lite.PredictionFunction;
import com.couchbase.lite.PredictiveIndex;
import com.couchbase.lite.PredictiveModel;
import com.couchbase.lite.ProtocolType;
import com.couchbase.lite.Query;
import com.couchbase.lite.QueryBuilder;
import com.couchbase.lite.ReplicatedDocument;
import com.couchbase.lite.Replicator;
import com.couchbase.lite.ReplicatorConfiguration;
import com.couchbase.lite.ReplicatorConnection;
import com.couchbase.lite.Result;
import com.couchbase.lite.ResultSet;
import com.couchbase.lite.SelectResult;
import com.couchbase.lite.SessionAuthenticator;
import com.couchbase.lite.URLEndpoint;
import com.couchbase.lite.ValueIndex;
import com.couchbase.lite.ValueIndexItem;
import com.couchbase.lite.Where;

public class Examples {
  private static final String TAG = "EXAMPLE ACTIVE PEER";
  private static final String ACTDBNAME = "local-database";
  private final Context context;
  // private Database database;
  // private Replicator replicator;

  public Examples(Context context) { this.context = context; }

  String user = "syncuser";
  String password = "sync9455";
  SecCertificate cert=null;
  String passivePeerEndpoint = "10.1.1.12:8920";
  String passivePeerPort = "8920";
  String passiveDbName = "userdb";
  Database actDb;
  Replicator thisReplicator;
  ListenerToken replicatorListener;

  //@Test
  // tag::p2p-act-rep-func[]
  public void testActPeerSync() throws CouchbaseLiteException, URISyntaxException {
    // tag::getting-started[]
// tag::p2p-act-rep-initialize[]
// Initialize the Couchbase Lite system
CouchbaseLite.init(context);

// Get the database (and create it if it doesn’t exist).
// DatabaseConfiguration config = new DatabaseConfiguration();
Database actDB = new Database("activepeerdb");

// Configure Sync Source and Target Endpoints
URL tgtUrl = new URL("wss://10.1.1.12:8092/passivepeerdb");
Endpoint targetEndpoint = new URLEndpoint(URI(tgtUrl));
ReplicatorConfiguration replConfig = new ReplicatorConfiguration(actDB, targetEndpoint); // <.>
// end::p2p-act-rep-initialize[]

    // Configure Sync Mode
    // tag::p2p-act-rep-config-type[]
    replConfig.setReplicatorType(ReplicatorConfiguration.ReplicatorType.PUSH_AND_PULL);
    // end::p2p-act-rep-config-type[]
    // tag::p2p-act-rep-config-cont[]
    replConfig.setContinuous(ReplicatorConfiguration.continuous=true);
    // end::p2p-act-rep-config-cont[]

    // tag::p2p-act-rep-config-self-cert[]
    // Configure Server Security
    replConfig.setDisableTLS(ReplicatorConfiguration.disableTLS=true);
    replConfig.setServerCertificateVerificationMode(ReplicatorConfiguration.serverCertificateVerificationMode=selfSignedCert); // <.>
    // end::p2p-act-rep-config-self-cert[]

    // tag::p2p-act-rep-config-cacert[]
    // ... other bits
    replConfig.getPinnedCertificate(ReplicatorConfiguration.getPinnedCertificate()); // Get listener cert if pinned
    // end::p2p-act-rep-config-cacert[]

    // Configure Client Security // <.>
    // tag::p2p-act-rep-auth[]
    // OPTIONALLY configure basic auth using user credentials
    Data thisPassword = new Data("password");
    replConfig.setAuthenticator(new BasicAuthenticator("username", thisPassword));
    // end::p2p-act-rep-auth[]
    // tag::p2p-tlsid-tlsidentity-with-label[]
    // Configure TLS Cert //
    // OPTIONALLY configure CA auth using key-stored cert id alias
    Data thisKeyPassword = new Data("thisKeyPassword--value")
    TLSIdentity thisIdentity = new TLSIdentity.getIdentity(alias: "doc-sync-server", keyPassword: thisKeyPassword ); // Get existing TLS ID from sec storage
    Authenticator thisAuthenticator = new ClientCertificateAuthenticator(thisIdentity);
    replConfig.setAuthenticator(thisAuthenticator);
    // end::p2p-tlsid-tlsidentity-with-label[]

    /* Optionally set custom conflict resolver call back */ replConfig.setConflictResolver( /* define resolver function */);

    // tag::p2p-act-rep-start-full[]
    // Create replicator (be sure to hold a reference somewhere that will prevent the Replicator from being GCed)
    Replicator thisReplicator = new Replicator(replConfig); // <.>

    // tag::p2p-act-rep-add-change-listener[]
    // Optionally add a change listener
    ListenerToken thisListener = new thisReplicator.addChangeListener(change -> { // <.>
      if (change.getStatus().getError() != null) {
        Log.i(TAG, "Error code ::  " + change.getStatus().getError().getCode());
      }
    });
    // end::p2p-act-rep-add-change-listener[]

    // tag::p2p-act-rep-start[]
    // Start replication.
    thisReplicator.start(); // <.>
    // end::p2p-act-rep-start[]
    // end::p2p-act-rep-start-full[]
    // end::p2p-act-rep-func[]

    // tag::p2p-act-rep-status[]
    Log.i(TAG, "The Replicator is currently " + thisReplicator.getStatus().getActivityLevel());
    Log.i(TAG, "The Replicator has processed " + t;

    if (thisReplicator.getStatus().getActivityLevel() == Replicator.ActivityLevel.BUSY) {
          Log.i(TAG, "Replication Processing");
          Log.i(TAG, "It has completed " + thisReplicator.getStatus().getProgess().getTotal() + " changes"");
      }
    // end::p2p-act-rep-status[]

    // tag::p2p-act-rep-stop[]
    // Stop replication.
    thisReplicator.stop(); // <.>
    // end::p2p-act-rep-stop[]
  }



