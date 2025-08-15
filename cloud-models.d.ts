
import { DataModelMethods } from "@cloudbase/wx-cloud-client-sdk";
interface IModalRefreshToke {}

interface IModalLoginStates {}

interface IModalIdentities {}

interface IModalUserRoles {}

interface IModalRoles {}

interface IModalSessions {}

interface IModalAudits {}

interface IModalJwkKeys {}

interface IModalOauthTokens {}

interface IModalOauthAuthC {}

interface IModalOauthClient {}

interface IModalUsers {}

interface IModalAuthcenter {}

interface IModalSysUser {}

interface IModalSysDepartment {}


interface IModels {

    /**
    * 数据模型：refresh_tokens
    */ 
    refresh_toke: DataModelMethods<IModalRefreshToke>;

    /**
    * 数据模型：login_states
    */ 
    login_states: DataModelMethods<IModalLoginStates>;

    /**
    * 数据模型：identities
    */ 
    identities: DataModelMethods<IModalIdentities>;

    /**
    * 数据模型：user_roles
    */ 
    user_roles: DataModelMethods<IModalUserRoles>;

    /**
    * 数据模型：roles
    */ 
    roles: DataModelMethods<IModalRoles>;

    /**
    * 数据模型：sessions
    */ 
    sessions: DataModelMethods<IModalSessions>;

    /**
    * 数据模型：audits
    */ 
    audits: DataModelMethods<IModalAudits>;

    /**
    * 数据模型：jwk_keys
    */ 
    jwk_keys: DataModelMethods<IModalJwkKeys>;

    /**
    * 数据模型：oauth_tokens
    */ 
    oauth_tokens: DataModelMethods<IModalOauthTokens>;

    /**
    * 数据模型：oauth_auth_codes
    */ 
    oauth_auth_c: DataModelMethods<IModalOauthAuthC>;

    /**
    * 数据模型：oauth_clients
    */ 
    oauth_client: DataModelMethods<IModalOauthClient>;

    /**
    * 数据模型：users
    */ 
    users: DataModelMethods<IModalUsers>;

    /**
    * 数据模型：authcenter
    */ 
    authcenter: DataModelMethods<IModalAuthcenter>;

    /**
    * 数据模型：用户
    */ 
    sys_user: DataModelMethods<IModalSysUser>;

    /**
    * 数据模型：部门
    */ 
    sys_department: DataModelMethods<IModalSysDepartment>;    
}

declare module "@cloudbase/wx-cloud-client-sdk" {
    interface OrmClient extends IModels {}
}

declare global {
    interface WxCloud {
        models: IModels;
    }
}