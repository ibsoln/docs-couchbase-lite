// tag::listener[]
listener code tbd
// end::listener[]
// tag::listener-config[]
listener config code tbd
// end::listener-config[]



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



