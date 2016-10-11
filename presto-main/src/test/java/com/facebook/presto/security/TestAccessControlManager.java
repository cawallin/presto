/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.facebook.presto.security;

import com.facebook.presto.block.BlockEncodingManager;
import com.facebook.presto.connector.ConnectorId;
import com.facebook.presto.metadata.MetadataManager;
import com.facebook.presto.metadata.QualifiedObjectName;
import com.facebook.presto.metadata.SchemaPropertyManager;
import com.facebook.presto.metadata.SessionPropertyManager;
import com.facebook.presto.metadata.TablePropertyManager;
import com.facebook.presto.server.PluginManagerConfig;
import com.facebook.presto.spi.CatalogSchemaTableName;
import com.facebook.presto.spi.PrestoException;
import com.facebook.presto.spi.SchemaTableName;
import com.facebook.presto.spi.connector.Connector;
import com.facebook.presto.spi.connector.ConnectorAccessControl;
import com.facebook.presto.spi.connector.ConnectorMetadata;
import com.facebook.presto.spi.connector.ConnectorSplitManager;
import com.facebook.presto.spi.connector.ConnectorTransactionHandle;
import com.facebook.presto.spi.security.Identity;
import com.facebook.presto.spi.security.Privilege;
import com.facebook.presto.spi.security.SystemAccessControl;
import com.facebook.presto.spi.security.SystemAccessControlFactory;
import com.facebook.presto.spi.transaction.IsolationLevel;
import com.facebook.presto.spi.type.TypeManager;
import com.facebook.presto.sql.analyzer.FeaturesConfig;
import com.facebook.presto.transaction.TransactionManager;
import com.facebook.presto.type.TypeRegistry;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.testng.annotations.Test;

import java.security.Principal;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static com.facebook.presto.security.AccessControlManager.ALLOW_ALL_ACCESS_CONTROL;
import static com.facebook.presto.spi.security.AccessDeniedException.denySelectTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denyShowCatalog;
import static com.facebook.presto.transaction.TransactionBuilder.transaction;
import static com.facebook.presto.transaction.TransactionManager.createTestTransactionManager;
import static java.util.Objects.requireNonNull;
import static org.testng.Assert.assertEquals;

public class TestAccessControlManager
{
    private static final Principal PRINCIPAL = new TestingPrincipal("principal");
    private static final String USER_NAME = "user_name";

    @Test(expectedExceptions = PrestoException.class, expectedExceptionsMessageRegExp = "Presto server is still initializing")
    public void testInitializing()
            throws Exception
    {
        AccessControlManager accessControlManager = new AccessControlManager(createTestTransactionManager(), new PluginManagerConfig());
        accessControlManager.checkCanSetUser(null, "foo");
    }

    @Test
    public void testNoneSystemAccessControl()
            throws Exception
    {
        AccessControlManager accessControlManager = new AccessControlManager(createTestTransactionManager(), new PluginManagerConfig());
        accessControlManager.setSystemAccessControl(ALLOW_ALL_ACCESS_CONTROL, ImmutableMap.<String, String>of());
        accessControlManager.checkCanSetUser(null, USER_NAME);
    }

    @Test
    public void testSetAccessControl()
            throws Exception
    {
        AccessControlManager accessControlManager = new AccessControlManager(createTestTransactionManager(), new PluginManagerConfig());

        TestSystemAccessControlFactory accessControlFactory = new TestSystemAccessControlFactory("test");
        accessControlManager.addSystemAccessControlFactory(accessControlFactory);
        accessControlManager.setSystemAccessControl("test", ImmutableMap.of());

        accessControlManager.checkCanSetUser(PRINCIPAL, USER_NAME);
        assertEquals(accessControlFactory.getCheckedUserName(), USER_NAME);
        assertEquals(accessControlFactory.getCheckedPrincipal(), PRINCIPAL);
    }

    @Test
    public void testNoCatalogAccessControl()
            throws Exception
    {
        TransactionManager transactionManager = createTestTransactionManager();
        AccessControlManager accessControlManager = new AccessControlManager(transactionManager, new PluginManagerConfig());

        TestSystemAccessControlFactory accessControlFactory = new TestSystemAccessControlFactory("test");
        accessControlManager.addSystemAccessControlFactory(accessControlFactory);
        accessControlManager.setSystemAccessControl("test", ImmutableMap.of());

        transaction(transactionManager)
                .execute(transactionId -> {
                    accessControlManager.checkCanSelectFromTable(transactionId, new Identity(USER_NAME, Optional.of(PRINCIPAL)), new QualifiedObjectName("catalog", "schema", "table"));
                });
    }

    @Test(expectedExceptions = PrestoException.class, expectedExceptionsMessageRegExp = "Access Denied: Cannot select from table schema.table")
    public void testDenyCatalogAccessControl()
            throws Exception
    {
        TransactionManager transactionManager = createTestTransactionManager();
        AccessControlManager accessControlManager = new AccessControlManager(transactionManager, new PluginManagerConfig());

        TestSystemAccessControlFactory accessControlFactory = new TestSystemAccessControlFactory("test");
        accessControlManager.addSystemAccessControlFactory(accessControlFactory);
        accessControlManager.setSystemAccessControl("test", ImmutableMap.of());

        registerBogusConnector(transactionManager, "connector");
        accessControlManager.addCatalogAccessControl(new ConnectorId("connector"), "catalog", new DenyConnectorAccessControl());

        transaction(transactionManager)
                .execute(transactionId -> {
                    accessControlManager.checkCanSelectFromTable(transactionId, new Identity(USER_NAME, Optional.of(PRINCIPAL)), new QualifiedObjectName("catalog", "schema", "table"));
                });
    }

    @Test(expectedExceptions = PrestoException.class, expectedExceptionsMessageRegExp = "Access Denied: Cannot select from table secured_catalog.schema.table")
    public void testDenySystemAccessControl()
            throws Exception
    {
        TransactionManager transactionManager = createTestTransactionManager();
        AccessControlManager accessControlManager = new AccessControlManager(transactionManager, new PluginManagerConfig());

        TestSystemAccessControlFactory accessControlFactory = new TestSystemAccessControlFactory("test");
        accessControlManager.addSystemAccessControlFactory(accessControlFactory);
        accessControlManager.setSystemAccessControl("test", ImmutableMap.of());

        registerBogusConnector(transactionManager, "connector");
        accessControlManager.addCatalogAccessControl(new ConnectorId("connector"), "secured_catalog", new DenyConnectorAccessControl());

        transaction(transactionManager)
                .execute(transactionId -> {
                    accessControlManager.checkCanSelectFromTable(transactionId, new Identity(USER_NAME, Optional.of(PRINCIPAL)), new QualifiedObjectName("secured_catalog", "schema", "table"));
                });
    }

    @Test(expectedExceptions = PrestoException.class, expectedExceptionsMessageRegExp = "Access Denied: Cannot show catalog catalog")
    public void testShowCatalogDenyCatalogAccessControl()
            throws Exception
    {
        TransactionManager transactionManager = createTestTransactionManager();
        AccessControlManager accessControlManager = new AccessControlManager(transactionManager, new PluginManagerConfig());

        TestSystemAccessControlFactory accessControlFactory = new TestSystemAccessControlFactory("test");
        accessControlManager.addSystemAccessControlFactory(accessControlFactory);
        accessControlManager.setSystemAccessControl("test", ImmutableMap.of());

        registerBogusConnector(transactionManager, "connector");
        accessControlManager.addCatalogAccessControl(new ConnectorId("connector"), "catalog", new DenyConnectorAccessControl());

        transaction(transactionManager)
                .execute(transactionId -> {
                    accessControlManager.checkCanShowCatalog(new Identity(USER_NAME, Optional.of(PRINCIPAL)), "catalog");
                });
    }

    @Test(expectedExceptions = PrestoException.class, expectedExceptionsMessageRegExp = "Access Denied: Cannot show catalog secured_catalog")
    public void testShowCatalogDenySystemAccessControl()
            throws Exception
    {
        TransactionManager transactionManager = createTestTransactionManager();
        AccessControlManager accessControlManager = new AccessControlManager(transactionManager, new PluginManagerConfig());

        TestSystemAccessControlFactory accessControlFactory = new TestSystemAccessControlFactory("test");
        accessControlManager.addSystemAccessControlFactory(accessControlFactory);
        accessControlManager.setSystemAccessControl("test", ImmutableMap.of());

        registerBogusConnector(transactionManager, "connector");
        accessControlManager.addCatalogAccessControl(new ConnectorId("connector"), "secured_catalog", new AllowConnectorAccessControl());

        transaction(transactionManager)
                .execute(transactionId -> {
                    accessControlManager.checkCanShowCatalog(new Identity(USER_NAME, Optional.of(PRINCIPAL)), "secured_catalog");
                });
    }

    @Test
    public void testShowCatalog()
    {
        TypeManager typeManager = new TypeRegistry();
        TransactionManager transactionManager = createTestTransactionManager();
        AccessControlManager accessControlManager = new AccessControlManager(transactionManager, new PluginManagerConfig());

        TestSystemAccessControlFactory accessControlFactory = new TestSystemAccessControlFactory("test");
        accessControlManager.addSystemAccessControlFactory(accessControlFactory);
        accessControlManager.setSystemAccessControl("test", ImmutableMap.of());

        registerBogusConnector(transactionManager, "safe_catalog");
        registerBogusConnector(transactionManager, "secured_catalog");
        registerBogusConnector(transactionManager, "another_secured_catalog");
        accessControlManager.addCatalogAccessControl(new ConnectorId("safe_catalog"), "safe_catalog", new AllowConnectorAccessControl());
        accessControlManager.addCatalogAccessControl(new ConnectorId("secured_catalog"), "secured_catalog", new AllowConnectorAccessControl());
        accessControlManager.addCatalogAccessControl(new ConnectorId("another_secured_catalog"), "another_secured_catalog", new DenyConnectorAccessControl());

        MetadataManager metadata = new MetadataManager(
                new FeaturesConfig().setExperimentalSyntaxEnabled(true),
                typeManager,
                new BlockEncodingManager(typeManager),
                new SessionPropertyManager(),
                new SchemaPropertyManager(),
                new TablePropertyManager(),
                transactionManager,
                accessControlManager);

        metadata.registerConnectorCatalog(new ConnectorId("safe_catalog"), "safe_catalog");
        metadata.registerConnectorCatalog(new ConnectorId("secured_catalog"), "secured_catalog");
        metadata.registerConnectorCatalog(new ConnectorId("another_secured_catalog"), "another_secured_catalog");

        Set<String> safe = metadata.getCatalogNames(Optional.of(new Identity(USER_NAME, Optional.of(PRINCIPAL)))).keySet();
        assertEquals(safe, ImmutableSet.of("safe_catalog"));

        Set<String> all = metadata.getCatalogNames(Optional.empty()).keySet();
        assertEquals(all, ImmutableSet.of("safe_catalog", "secured_catalog", "another_secured_catalog"));
    }

    private static void registerBogusConnector(TransactionManager transactionManager, String connectorId)
    {
        transactionManager.addConnector(new ConnectorId(connectorId), new Connector()
        {
            @Override
            public ConnectorTransactionHandle beginTransaction(IsolationLevel isolationLevel, boolean readOnly)
            {
                // Just return something
                return new ConnectorTransactionHandle() {};
            }

            @Override
            public ConnectorMetadata getMetadata(ConnectorTransactionHandle transactionHandle)
            {
                throw new UnsupportedOperationException();
            }

            @Override
            public ConnectorSplitManager getSplitManager()
            {
                throw new UnsupportedOperationException();
            }
        });
    }

    private static class TestSystemAccessControlFactory
            implements SystemAccessControlFactory
    {
        private final String name;
        private Map<String, String> config;

        private Principal checkedPrincipal;
        private String checkedUserName;

        public TestSystemAccessControlFactory(String name)
        {
            this.name = requireNonNull(name, "name is null");
        }

        public Map<String, String> getConfig()
        {
            return config;
        }

        public Principal getCheckedPrincipal()
        {
            return checkedPrincipal;
        }

        public String getCheckedUserName()
        {
            return checkedUserName;
        }

        @Override
        public String getName()
        {
            return name;
        }

        @Override
        public SystemAccessControl create(Map<String, String> config)
        {
            this.config = config;
            return new SystemAccessControl()
            {
                @Override
                public void checkCanSetUser(Principal principal, String userName)
                {
                    checkedPrincipal = principal;
                    checkedUserName = userName;
                }

                @Override
                public void checkCanSetSystemSessionProperty(Identity identity, String propertyName)
                {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void checkCanShowCatalog(Identity identity, String catalogName)
                {
                    if (catalogName.equals("secured_catalog")) {
                        denyShowCatalog(catalogName);
                    }
                }

                @Override
                public void checkCanSelectFromTable(Identity identity, CatalogSchemaTableName table)
                {
                    if (table.getCatalogName().equals("secured_catalog")) {
                        denySelectTable(table.toString());
                    }
                }
            };
        }
    }

    private static class DenyConnectorAccessControl
            implements ConnectorAccessControl
    {
        @Override
        public void checkCanShowCatalog(Identity identity, String catalogName)
        {
            denyShowCatalog(catalogName);
        }

        @Override
        public void checkCanSelectFromTable(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            denySelectTable(tableName.toString());
        }

        @Override
        public void checkCanCreateSchema(ConnectorTransactionHandle transactionHandle, Identity identity, String schemaName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanDropSchema(ConnectorTransactionHandle transactionHandle, Identity identity, String schemaName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanRenameSchema(ConnectorTransactionHandle transactionHandle, Identity identity, String schemaName, String newSchemaName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanCreateTable(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanDropTable(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanRenameTable(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName, SchemaTableName newTableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanAddColumn(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanRenameColumn(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanInsertIntoTable(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanDeleteFromTable(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanCreateView(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName viewName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanDropView(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName viewName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanSelectFromView(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName viewName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanCreateViewWithSelectFromTable(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanCreateViewWithSelectFromView(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName viewName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanSetCatalogSessionProperty(Identity identity, String propertyName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanGrantTablePrivilege(ConnectorTransactionHandle transactionHandle, Identity identity, Privilege privilege, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanRevokeTablePrivilege(ConnectorTransactionHandle transactionHandle, Identity identity, Privilege privilege, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }
    }

    private static class AllowConnectorAccessControl
            implements ConnectorAccessControl
    {
        @Override
        public void checkCanShowCatalog(Identity identity, String catalogName)
        {
        }

        @Override
        public void checkCanSelectFromTable(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanCreateTable(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanDropTable(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanRenameTable(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName, SchemaTableName newTableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanAddColumn(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanRenameColumn(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanInsertIntoTable(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanDeleteFromTable(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanCreateView(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName viewName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanDropView(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName viewName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanSelectFromView(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName viewName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanCreateViewWithSelectFromTable(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanCreateViewWithSelectFromView(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName viewName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanSetCatalogSessionProperty(Identity identity, String propertyName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanGrantTablePrivilege(ConnectorTransactionHandle transactionHandle, Identity identity, Privilege privilege, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkCanRevokeTablePrivilege(ConnectorTransactionHandle transactionHandle, Identity identity, Privilege privilege, SchemaTableName tableName)
        {
            throw new UnsupportedOperationException();
        }
    }
}
