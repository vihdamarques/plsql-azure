create or replace package pkg_azure as
  -- Globals
  RESOURCE_KEYVAULT    varchar2(255) := 'https://vault.azure.net';
  RESOURCE_BLOB        varchar2(255) := 'https://%s.blob.core.windows.net';
  API_VERSION_STORAGE  varchar2(255) := '2019-12-12';
  API_VERSION_KEYVAULT varchar2(255) := '7.1';
  -- Types
  subtype s_name is varchar2(255);
  subtype s_value is varchar2(32767);
  type t_headers is table of s_value index by s_name;
  type r_binary_response is record (file_name varchar2(500), mime_type varchar2(255), file_data blob);
  type r_text_response is record (mime_type varchar2(255), text_data clob);
  --
  subtype s_resource is varchar2(255);
  subtype s_client_id is varchar2(255);
  subtype s_tenant_id is varchar2(255);
  type r_token is record (token varchar2(32767), expires_on date);
  type t_token_res is table of r_token index by s_resource;
  type t_token_cli is table of t_token_res index by s_client_id;
  type t_token is table of t_token_cli index by s_tenant_id;
  --
  type r_blob_list is record (
    file_name      varchar2(255),
    creation_time  date,
    last_modified  date,
    content_length number,
    content_type   varchar2(255),
    checksum       varchar2(255)
  );
  type t_blob_list is table of r_blob_list;

  -- Call at least once before other calls
  procedure set_config(p_tenant_id     in varchar2,
                       p_client_id     in varchar2,
                       p_client_secret in varchar2,
                       p_wallet_path   in varchar2 default null,
                       p_wallet_pass   in varchar2 default null);

  -- Azure Key Vault
  function keyvault_get_secret(p_vault_name in varchar2, p_secret_name in varchar2) return varchar2;

  -- Azure Storage Account
  function storage_list_blobs(p_account in varchar2, p_container in varchar2, p_prefix in varchar2) return t_blob_list;
  function storage_get_blob(p_account in varchar2, p_container in varchar2, p_blob_name in varchar2) return blob;
  procedure storage_put_blob(p_account   in varchar2,
                             p_container in varchar2,
                             p_blob_name in varchar2,
                             p_content   in blob,
                             p_mime_type in varchar2 default null);
end pkg_azure;
/