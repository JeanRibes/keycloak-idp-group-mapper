package ovh.ribes.jean.keycloak.groupmapper;

import com.google.auto.service.AutoService;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.broker.oidc.KeycloakOIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.mappers.AbstractClaimMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.*;

import static org.keycloak.models.IdentityProviderSyncMode.FORCE;
import static org.keycloak.models.IdentityProviderSyncMode.IMPORT;

@JBossLog
@AutoService(IdentityProviderMapper.class)
public class ClaimToGroupMapper extends AbstractClaimMapper {
    public static final String[] COMPATIBLE_PROVIDERS = {KeycloakOIDCIdentityProviderFactory.PROVIDER_ID, OIDCIdentityProviderFactory.PROVIDER_ID};
    public static final String GROUP = "group";
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    public static final String PROVIDER_ID = "oidc-group-idp-mapper";
    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES = new HashSet<>(Arrays.asList(IMPORT, FORCE));

    public GroupModel getGroup(final RealmModel realm, final IdentityProviderMapperModel mapperModel) {
        String groupId = mapperModel.getConfig().get(GROUP);
        System.out.println(groupId);
        GroupModel group = realm.getGroupById(groupId);
        if (group == null) {
            throw new IdentityBrokerException("Unable to find group with ID " + groupId);
        }
        return group;
    }

    protected boolean applies(final IdentityProviderMapperModel mapperModel, final BrokeredIdentityContext context) {
        return super.hasClaimValue(mapperModel, context);
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        if (applies(mapperModel, context)) {
            GroupModel group = this.getGroup(realm, mapperModel);
            user.joinGroup(group);
        }
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        GroupModel group = this.getGroup(realm, mapperModel);
        if (applies(mapperModel, context)) {
            user.joinGroup(group);
        } else {
            user.leaveGroup(group);
        }
    }

    static {
        ProviderConfigProperty property;
        ProviderConfigProperty property1;
        property1 = new ProviderConfigProperty();
        property1.setName(CLAIM);
        property1.setLabel("Claim");
        property1.setHelpText("Name of claim to search for in token. You can reference nested claims using a '.', i.e. 'address.locality'. To use dot (.) literally, escape it with backslash (\\.)");
        property1.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property1);
        property1 = new ProviderConfigProperty();
        property1.setName(CLAIM_VALUE);
        property1.setLabel("Claim Value");
        property1.setHelpText("Value the claim must have.  If the claim is an array, then the value must be contained in the array.");
        property1.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property1);
        property = new ProviderConfigProperty();
        property.setName(GROUP);
        property.setLabel("Group ID");
        property.setHelpText("Group ID");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Group Importer";
    }

    @Override
    public String getDisplayType() {
        return "Claim to Group";
    }

    @Override
    public String getHelpText() {
        return "If the specified claim has a specific value, make the user join the specified group. Otherwise the user will be removed from that group";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return IDENTITY_PROVIDER_SYNC_MODES.contains(syncMode);
    }
}
