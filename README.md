# plsql-azure

PL/SQL package to handle some of Microsoft Azure functionalities. New features are going to be added on demand. Feel free to pull request enhancements.

## Requirements

This package requires [Oracle APEX 5.1+](http://apex.oracle.com) installed in database since it uses the packages: APEX_STRING and APEX_JSON.

## Current Functionalities

* Key Vault
  * Get Secret
* Storage Account
  * List Blobs
  * Get Blob
  * Put Blob

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

List Blobs

    declare
      l_blob_list pkg_azure.t_blob_list;
    begin
      l_blob_list := pkg_azure.storage_list_blobs('account_name', 'container_name', 'prefix');
      for i in 1 .. l_blob_list.count loop
        dbms_output.put_line(l_blob_list(i).file_name);
      end loop;
    end;
    /

Get Blob

    select pkg_azure.storage_get_blob('account_name', 'container_name', 'path') from dual;

Put Blob

    declare
      l_dummy_file blob := utl_raw.cast_to_raw('Dummy');
    begin
      pkg_azure.storage_put_blob('account_name', 'container_name', 'path', l_dummy_file, 'text/plain');
      dbms_lob.freeTemporary(l_dummy_file);
    end;
    /
