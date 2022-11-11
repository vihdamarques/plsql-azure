# plsql-azure

PL/SQL package to handle some of Microsoft Azure features via web service. New features are going to be added on demand. Feel free to pull request enhancements.

## Requirements

This package requires [Oracle APEX 5.1+](http://apex.oracle.com) installed in database since it uses the packages: APEX_STRING and APEX_JSON.

## Current Features

- Key Vault
  - Get Secret
- Storage Account
  - Blob Storage (Container)
    - List Blobs
    - Get Blob
    - Put Blob
  - Queues
    - Get Queue Messages
    - Peek Queue Messages
    - Put Queue Message
    - Delete Queue Message

## Examples

### Configuration

Set credentials (aways do this before making a call for the first time):

    begin
      pkg_azure.set_config (
        p_tenant_id     => 'tenant_id',
        p_client_id     => 'client_id',
        p_client_secret => 'client_secret',
        p_wallet_path   => 'wallet_path',
        p_wallet_pass   => 'wallet_pass'
      );
    end;
    /

### Key Vault

Get Key Vault Secret

    select pkg_azure.keyvault_get_secret('vault_name', 'secret_name') from dual;

### Storage Account

#### Blob Storage (Container)

List Blobs

    declare
      l_blob_list pkg_azure.t_blob_list;
    begin
      l_blob_list := pkg_azure.storage_blob_list('account_name', 'container_name', 'prefix');
      for i in 1 .. l_blob_list.count loop
        dbms_output.put_line(l_blob_list(i).file_name);
      end loop;
    end;
    /

Get Blob

    select pkg_azure.storage_blob_get('account_name', 'container_name', 'path') from dual;

Put Blob

    declare
      l_dummy_file blob := utl_raw.cast_to_raw('Dummy');
    begin
      pkg_azure.storage_blob_put('account_name', 'container_name', 'path', l_dummy_file, 'text/plain');
      dbms_lob.freeTemporary(l_dummy_file);
    end;
    /

#### Queues

Get Queue Messages

    declare
      l_queue_list := pkg_azure.t_queue_list;
    begin
      l_queue_list := pkg_azure.storage_queue_get(p_account => 'account_name',
                                                  p_queue   => 'queue_name');
      for i in 1 .. l_queue_list.count loop
        dbms_output.put_line(l_queue_list(i).message_text);
      end loop;
    end;
    /

Peek Queue Messages

    declare
      l_queue_list := pkg_azure.t_queue_list;
    begin
      l_queue_list := pkg_azure.storage_queue_peek(p_account => 'account_name',
                                                   p_queue   => 'queue_name');
      for i in 1 .. l_queue_list.count loop
        dbms_output.put_line(l_queue_list(i).message_text);
      end loop;
    end;
    /

Put Queue Message

    declare
      l_queue_entry := pkg_azure.r_queue_entry;
    begin
      l_queue_entry := pkg_azure.storage_queue_put(p_account => 'account_name',
                                                   p_queue   => 'queue_name',
                                                   p_message => 'test message');
    end;
    /

Delete Queue Message

    declare
      l_queue_list := pkg_azure.t_queue_list;
    begin
      l_queue_list := pkg_azure.storage_queue_get(p_account         => 'account_name',
                                                  p_queue           => 'queue_name',
                                                  p_num_of_messages => 1);

      pkg_azure.storage_queue_delete(p_account     => 'account_name',
                                     p_queue       => 'queue_name',
                                     p_message_id  => l_queue_list(1).message_id,
                                     p_pop_receipt => l_queue_list(1).pop_receipt);
    end;
    /
