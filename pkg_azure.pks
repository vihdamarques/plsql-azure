create or replace package pkg_azure as
  -- Globals
  RESOURCE_KEYVAULT      varchar2(255) := 'https://vault.azure.net';
  RESOURCE_STORAGE_BLOB  varchar2(255) := 'https://%s.blob.core.windows.net';
  RESOURCE_STORAGE_QUEUE varchar2(255) := 'https://%s.queue.core.windows.net';
  API_VERSION_STORAGE    varchar2(255) := '2021-08-06';
  API_VERSION_KEYVAULT   varchar2(255) := '7.1';

  -- Types
  subtype s_name is varchar2(255);
  subtype s_value is varchar2(32767);
  type t_headers is table of s_value index by s_name;
  type r_binary_response is record (
    status_code number(3),
    file_name varchar2(500),
    mime_type varchar2(255),
    file_data blob
  );
  type r_text_response is record (
    status_code number(3),
    mime_type varchar2(255),
    text_data clob
  );
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
  type r_queue_entry is record (
    message_id varchar2(255),
    insertion_time date,
    expiration_time date,
    time_next_visible date,
    pop_receipt varchar2(255),
    dequeue_count number,
    message_text clob
  );
  type t_queue_list is table of r_queue_entry;

  -- Call at least once before other calls
  procedure set_config(p_tenant_id     in varchar2,
                       p_client_id     in varchar2,
                       p_client_secret in varchar2,
                       p_wallet_path   in varchar2 default null,
                       p_wallet_pass   in varchar2 default null);

  -- Azure Key Vault
  function keyvault_get_secret(p_vault_name in varchar2, p_secret_name in varchar2) return varchar2;

  -- Azure Storage Account
  function storage_blob_list(p_account   in varchar2,
                             p_container in varchar2,
                             p_prefix    in varchar2)
  return t_blob_list;

  function storage_blob_get(p_account   in varchar2,
                            p_container in varchar2,
                            p_blob_name in varchar2)
  return blob;

  procedure storage_blob_put(p_account   in varchar2,
                             p_container in varchar2,
                             p_blob_name in varchar2,
                             p_content   in blob,
                             p_mime_type in varchar2 default null);

  function storage_queue_get(p_account            in varchar2,
                             p_queue              in varchar2,
                             p_num_of_messages    in number default null,
                             p_visibility_timeout in number default null,
                             p_timeout            in number default null,
                             p_peek_only          in boolean default false)
  return t_queue_list;

  function storage_queue_peek(p_account         in varchar2,
                              p_queue           in varchar2,
                              p_num_of_messages in number default null,
                              p_timeout         in number default null)
  return t_queue_list;

  function storage_queue_put(p_account            in varchar2,
                             p_queue              in varchar2,
                             p_message            in clob, -- Max 65.536 caracteres (64K bytes) / must either be XML-escaped or Base64-encode / Ex: <QueueMessage><MessageText>message-content</MessageText></QueueMessage>
                             p_visibility_timeout in number default null,
                             p_message_ttl        in number default null, -- max 7 dias (604.800 segundos)
                             p_timeout            in number default null)
  return r_queue_entry;

  procedure storage_queue_delete(p_account     in varchar2,
                                 p_queue       in varchar2,
                                 p_message_id  in varchar2,
                                 p_pop_receipt in varchar2 default null,
                                 p_timeout     in number   default null);
end pkg_azure;
/