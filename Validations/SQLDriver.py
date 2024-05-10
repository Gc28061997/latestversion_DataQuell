
# import os
# import config
# import adal
# import pandas as pd
# import struct
# import pyodbc
# import mysql.connector
# import hashlib
# import pymysql
# import pymssql
# import asyncio
# import warnings
# import ssl
# warnings.filterwarnings("ignore", category=UserWarning)

# async def GetSQLDF(table_name, User, Password, Database):

#     server='mysqladf.mysql.database.azure.com'
#     # Establish a connection to the database
#     conn = pymysql.connect(
#         host=server,
#         user=User,
#         password=Password,
#         database=Database,
#     )

#     # Create a cursor object
#     cursor = conn.cursor()

#     # Execute the columns query
#     columns_query = f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table_name}' ORDER BY ORDINAL_POSITION"
#     cursor.execute(columns_query)



#     # Fetch the columns from the query result
#     columns = cursor.fetchall()

#     columns = [column[0] for column in columns]

#     # Get the first column and generate the SELECT query with dynamic hash code
#     first_column = columns[0]
#     print("first_coulmn", first_column)
#     columns_name = ','.join(columns)
#     # select_query = f"SELECT {first_column}, SHA2(CONCAT(',', {columns_name}), 256) AS hash FROM {table_name}"
#     select_query = f"SELECT {first_column}, SHA2(CONCAT({columns_name}), 256) AS hash FROM {table_name}"



#     # Execute the SELECT query and retrieve the results into a DataFrame
#     cursor.execute(select_query)
#     data = cursor.fetchall()
#     data = pd.DataFrame(data, columns=[first_column, 'hash'])
#     # Close the cursor and the database connection
#     cursor.close()
#     conn.close()
#     # print("Source Data: ",data)
#     return data




# # FOR MSSQL DATAFRAME

# async def GetMSSQLDF( table_name, User, Password, Database):
# # Establishing the connection
#     Server ='adf-framework.database.windows.net'

#     # engine1 = f'DRIVER={{SQL Server}};SERVER={Server};DATABASE={Database};UID={User};PWD={Password}'

#     # # # Connect to the database
#     # engine = pyodbc.connect(engine1)

#     # Create a cursor object
#     engine=pymssql.connect(host=Server,user=User,password=Password,database=Database)

#     columns_query = f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table_name}' ORDER BY ORDINAL_POSITION"
#     columns = pd.read_sql_query(columns_query, engine)['COLUMN_NAME']
#     # Get the first column and generate the SELECT query with dynamic hash code
#     first_column = columns[0]
#     columns = pd.Series(columns)
#     columns_name = ','.join(columns.astype(str))

  
   
#     #select_query = f"SELECT {first_column}, CONVERT(VARCHAR(64), HASHBYTES('SHA2_256', CONCAT({columns_name})), 2) AS hash FROM {table_name}"
#     select_query = f"SELECT {first_column}, LOWER(CONVERT(VARCHAR(64), HASHBYTES('SHA2_256', CONCAT({columns_name})), 2)) AS hash FROM {table_name}"
#     # Execute the SQL query and retrieve the results into a DataFrame
#     data = pd.read_sql_query(select_query, engine)

#     engine.close()

#     return data







# async def ExecuteSQLQuery(table1, table2):
#     df_Source = GetSQLDF(table1)
#     df_Destination = GetMSSQLDF(table2)
    
#     source_row = df_Source.shape[0]
#     print("Source rows count =", source_row)

#     destination_rows = df_Destination.shape[0]
#     print("Destination rows count =", destination_rows)

#     if source_row == destination_rows:
#         df_source = df_Source[['Id']]
#         df_destination = df_Destination[['Id']]

#         compare = df_source.compare(df_destination, result_names=("Source", "Destination"))

#         get_data = compare.index
#         get_data = [i + 1 for i in get_data]

#         source_error_df = df_Source[df_Source.Id.isin(get_data)].sort_index()
#         source_error_df = source_error_df.loc[:, source_error_df.columns != 'hash']

#         destination_error_df = df_Destination[df_Destination.Id.isin(get_data)].sort_index()
#         destination_error_df = destination_error_df.loc[:, destination_error_df.columns != 'hash']
#     else:
#         print("DataFrame Row Count Not Matched")






import pandas as pd
import pymysql
import warnings

import pymssql
warnings.filterwarnings("ignore", category=UserWarning)

async def GetSQLDF(table_name, User, Password, Database):
    server = 'mysqladf.mysql.database.azure.com'
    conn = pymysql.connect(
        host=server,
        user=User,
        password=Password,
        database=Database,
    )
    cursor = conn.cursor()
    
    columns_query = f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table_name}' ORDER BY ORDINAL_POSITION"
    cursor.execute(columns_query)
    columns = cursor.fetchall()
    columns = [column[0] for column in columns]
    
    first_column = columns[0]
    columns_name = ','.join(columns)
    select_query = f"SELECT {first_column}, MD5(CONCAT({columns_name})) AS hash FROM {table_name}"
    
    cursor.execute(select_query)
    data = cursor.fetchall()
    data = pd.DataFrame(data, columns=[first_column, 'hash'])
    
    cursor.close()
    conn.close()
    
    return data

async def GetMSSQLDF(table_name, User, Password, Database):
    Server = 'adf-framework.database.windows.net'
    engine = pymssql.connect(host=Server, user=User, password=Password, database=Database)
    
    columns_query = f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table_name}' ORDER BY ORDINAL_POSITION"
    columns = pd.read_sql_query(columns_query, engine)['COLUMN_NAME']
    
    first_column = columns[0]
    columns = pd.Series(columns)
    columns_name = ','.join(columns.astype(str))
    
    select_query = f"SELECT {first_column}, LOWER(CONVERT(VARCHAR(64), HASHBYTES('MD5', CONCAT({columns_name})), 2)) AS hash FROM {table_name}"
    data = pd.read_sql_query(select_query, engine)
    
    engine.close()
    
    return data

async def ExecuteSQLQuery(table1, table2, User1, Password1, Database1, User2, Password2, Database2):
    df_Source = await GetSQLDF(table1, User1, Password1, Database1)
    df_Destination = await GetMSSQLDF(table2, User2, Password2, Database2)
    
    source_row = df_Source.shape[0]
    destination_rows = df_Destination.shape[0]
    
    if source_row == destination_rows:
        df_source = df_Source[['Id']]
        df_destination = df_Destination[['Id']]

        compare = df_source.compare(df_destination, result_names=("Source", "Destination"))

        get_data = compare.index
        get_data = [i + 1 for i in get_data]

        source_error_df = df_Source[df_Source.Id.isin(get_data)].sort_index()
        source_error_df = source_error_df.loc[:, source_error_df.columns != 'hash']

        destination_error_df = df_Destination[df_Destination.Id.isin(get_data)].sort_index()
        destination_error_df = destination_error_df.loc[:, destination_error_df.columns != 'hash']
    else:
        print("DataFrame Row Count Not Matched")

