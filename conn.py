# # import pyodbc
# # server = 'db-connect-fs.database.windows.net'
# # database = 'sql_validation'
# # username = 'mysqlserverdb'
# # password = 'validation@123'

# # connection_string = f'DRIVER={{ODBC Driver 18 for SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password}'

# # conn = pyodbc.connect(connection_string)


# # cursor = conn.cursor()



# # # Execute an SQL query
# # cursor.execute('SELECT * FROM User_Data')


# # rows = cursor.fetchall()
# # for row in rows:
# #     print(row)

# # cursor.close()
# # conn.close()

# import pyodbc
# server = 'db-connect-fs.database.windows.net'
# database = 'sql_validation'
# username = 'mysqlserverdb'
# password = 'validation@123'
# conn_str = f'DRIVER={{SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password}'

# # Connect to the database
# conn = pyodbc.connect(conn_str)

# # Create a cursor object
# cursor = conn.cursor()

# # Execute a sample query
# cursor.execute('SELECT * FROM User_Data')

# # Fetch the results
# results = cursor.fetchall()

# # Process the results
# for row in results:
#     print(row)

# # Close the cursor and connection
# cursor.close()
# conn.close()




from azure.storage.blob import BlobServiceClient

def export_csv_from_blob(account_name, account_key, container_name, blob_name, local_file_path):
    try:
        # Create a BlobServiceClient
        blob_service_client = BlobServiceClient(account_url=f"https://{account_name}.blob.core.windows.net", credential=account_key)

        # Get the Blob Client for the specific blob
        container_client = blob_service_client.get_container_client(container_name)
        blob_client = container_client.get_blob_client(blob_name)

        # Download the blob to a local file
        with open(local_file_path, "wb") as file:
            blob_data = blob_client.download_blob()
            file.write(blob_data.readall())

        print(f"CSV file '{blob_name}' has been exported to '{local_file_path}' successfully.")

    except Exception as e:
        print(f"An error occurred: {e}")

# Replace these values with your actual Azure Storage account credentials and container/blob details
account_name = "storagedemoreema "
account_key = "WvSKPpb60HuiIri1X1nYtk5h0RPzO6/UKnjS8FIl5UKHF0YwR/NGGTap0FZ/xrjKhGhuQ6YaHPzx+AStu9kgxw=="
container_name = "validation"
blob_name = "User_Data.csv"  # Replace with the name of the CSV file in the container
local_file_path = r"C:\rulengine_master\User_Data.csv"

export_csv_from_blob(account_name, account_key, container_name, blob_name, local_file_path)
