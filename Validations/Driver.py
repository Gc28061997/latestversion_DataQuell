# # Databricks notebook source
# import json
# import pandas as pd
# import numpy as np
# from datetime import datetime
# import configparser
# import os

# from Validations.CsvParser import getDFfromCsv, getDFfromXlsxMerge, getDFfromXls, check_dtype, check_ruleValidation,getDFfromXlsx
# from Validations.JsonParser import GetAllValueByKey, GetRules
# from Validations.Utility import getUniqueValueList, list_contains

# # MAGIC %run /Shared/DFP/RuleEngine/RuleEngineDev/CleanupFiles

# # COMMAND ----------

# # MAGIC %run /Shared/DFP/RuleEngine/RuleEngineDev/QueryBuilder

# # COMMAND ----------

# # MAGIC %run /Shared/DFP/RuleEngine/RuleEngineDev/JsonParser

# # COMMAND ----------

# # MAGIC %run /Shared/DFP/RuleEngine/RuleEngineDev/CsvParser

# # COMMAND ----------

# # MAGIC %run /Shared/DFP/RuleEngine/RuleEngineDev/Utility

# # COMMAND ----------

# # fileName geting from ADF pipeline

# from Validations.CsvParser import getDFfromCsv, getDFfromXlsxMerge, getDFfromXls, check_dtype, check_ruleValidation,getDFfromXlsx
# from Validations.JsonParser import GetAllValueByKey, GetRules
# from Validations.Utility import getUniqueValueList, list_contains

# # data= '{"RuleID": "10","RuleName": "ValidData_1.csv_email validation","DataAttribute": "email","DataType": "String","ValidationOperator": "Regular Expression","ValueToBeMatch": "","Order": "10","DataObject": "table","DataSource": "ValidData_1.csv","Sequence": "10"}'
# # def run_driver(request):
# def run_driver():
#     # request = json.loads(request)
#     # configFilePathCntnr = request.get("DataSource")
#     # print("configpath =>>>>",configFilePathCntnr)

#     # COMMAND ----------

#     # Read the App configuraiton ruleEngineConfiguraitonXls.ini
#     # mountPath = '/dbfs/mnt'
#     # mountPathXlsx = 'dbfs:/mnt'
#     #configFilePath = configFilePathCntnr
#     configFilePath= "configuration.ini"
#     # stage_dir = "/dbfs/mnt/sgre-apps/data_validation_engine/"
#     subject = 'Data_Validation'
#     parser = configparser.ConfigParser()
#     parser.read(configFilePath)

#     #ruleFilePath = request.get('RULE_FILE_PATH')
#     ruleFilePath=parser.get('APP', 'RULE_FILE_PATH')
#     Column_address=parser.get('SOURCE', 'COLUMN_ADDRESS')
#     Column_address1=parser.get('SOURCE', 'COLUMN_ADDRESS1')
#     sheet_name=parser.get('SOURCE', 'sheet_name')

#     print(Column_address)
    
#     print("rule file path",ruleFilePath)
#     outputDir = parser.get('APP', 'OUTPUT_FILE_PATH')
#     reportOutputDir = outputDir + '/report/'
#     errorOutputDir = outputDir + '/error/'
#     rules = GetRules(ruleFilePath)
#     print("Total rules in the rule file - ", len(rules))

#     date = datetime.now().strftime("%Y%m%d_%I%M%S")
#     TablesName = GetAllValueByKey(rules, "DataObject")
#     TableList = getUniqueValueList(TablesName)

#     # Data type validatoin
#     sysValidDataTypeList = ['int', 'string', 'bool', 'float']
#     temp = GetAllValueByKey(rules, "DataType")
#     dataTypeList = getUniqueValueList(temp)
#     dataTypeValidation = list_contains(sysValidDataTypeList, dataTypeList)
#     print("Data type in rule file is valid - " + str(dataTypeValidation))

#     # Operator validation
#     sysValOperatorList = ['regex', 'reference', 'notnull', ]
#     temp = GetAllValueByKey(rules, "ValidationOperator")
#     operatorList = getUniqueValueList(temp)
#     operatorValidator = list_contains(sysValOperatorList, operatorList)
#     print("Operator validation in rule file is valid - " + str(operatorValidator))

#     SOURCE_TYPE = parser.get('APP', 'SOURCE_TYPE')
#     SOURCE_DATA_FILE_PATH = parser.get('SOURCE', 'SOURCE_DATA_FILE_PATH')
#     SOURCE_DATA_FILE_PATH_XLS =  parser.get('SOURCE', 'SOURCE_DATA_FILE_PATH')
#     SKIP_ROWS = parser.get('SOURCE', 'SKIP_ROWS')

#     csvdf = pd.DataFrame()
#     # Read the CSV
#     if SOURCE_TYPE == 'CSV':
#         csvdf = getDFfromCsv(SOURCE_DATA_FILE_PATH, SKIP_ROWS) 
#         no_of_rows,no_of_columns=csvdf.shape   


#     # Read the XLS
#     if SOURCE_TYPE == 'XLS':
#         csvdf = getDFfromXls(SOURCE_DATA_FILE_PATH, SKIP_ROWS)
#         no_of_rows,no_of_columns=csvdf.shape

#     # Read the XLSX
#     if SOURCE_TYPE == 'XLSX':
#         #csvdf = getDFfromXlsxMerge(SOURCE_DATA_FILE_PATH, SKIP_ROWS)
#         csvdf= getDFfromXlsx(SOURCE_DATA_FILE_PATH, sheet_name,Column_address,Column_address1,SKIP_ROWS)
#         no_of_rows,no_of_columns=csvdf.shape
       
        

#     dtp = []
#     for colName in csvdf.columns.tolist():
#         dtp.append(check_dtype(csvdf, colName))

#     ruleColList = GetAllValueByKey(rules, "DataAttribute")
#     ruleColList = getUniqueValueList(ruleColList)

#     csvColList = csvdf.columns
#     csvColList = getUniqueValueList(csvColList)   

#     csvcolValidator = list_contains(ruleColList, csvColList)
#     rulcolValidator = list_contains(csvColList, ruleColList)

#     df_rule = pd.DataFrame(rules)
#     df_rdf = pd.DataFrame()
#     df_rdf = df_rule[['RuleID', 'Sequence' ,'DataAttribute', 'DataType']]
#     df_rdf = df_rdf.loc[df_rdf['Sequence'].notna()]
#     df_rdf.sort_values(by=['Sequence'], ascending=False)
#     df_rdf = df_rdf.drop_duplicates(['DataAttribute', 'DataType'], keep='first').reset_index(drop=True)
#     df_csv = pd.DataFrame(list(zip(csvColList, dtp)),columns=['CSV_Col_Name', 'CsvDataType'])
#     cols_index = [(csvdf.columns.get_loc(col)+1) for col in csvColList]
#     df_rdf = df_rdf.assign(CsvSequence = cols_index)
#     df_rdf['CsvSequence'] = df_rdf['CsvSequence'].astype(str)
    
#     bigdata = pd.concat([df_rdf, df_csv], axis=1).reindex(df_rdf.index)
    
#     bigdata['CsvDataType'] = np.where(bigdata['CsvDataType'] == 'pass', bigdata['DataType'], bigdata['CsvDataType'])
#     # print(bigdata['CsvDataType']) 
#     bigdata['CsvDataType'] = np.where(bigdata['DataType'] == 'date', bigdata['DataType'], bigdata['CsvDataType'])

#     bigdata['Data_Type_Match'] = np.where(bigdata['DataType'] == bigdata['CsvDataType'], 'True', 'False')
    
   
#     bigdata['Column_Match'] = np.where(df_rdf['DataAttribute'] == bigdata['CSV_Col_Name'], 'True', 'False')
    
#     bigdata['SequenceMatch'] = np.where(df_rdf['CsvSequence']== df_rdf['Sequence'], 'True', 'False')
    
    
#     # Write bigdata dataframe to a csv
#     Rule_Summary = pd.DataFrame(columns=['RuleId', 'RuleName',  'ColumnName', 'Validation_Result','Datatype_RuleFile','Datatype_OrignalFile','Datatype_Match','RuleSequence','SequenceMatch'])
                       

#     if "False" in list(bigdata['Data_Type_Match']) :
#         Data_Type_Match_Flag = "Fail"
#     else:
#         Data_Type_Match_Flag = "Pass"

#     if "False" in list(bigdata['Column_Match']) or "False" in list(bigdata['SequenceMatch']):
#         Column_Match_Flag = "Fail"
#         Sequence_Match_Flag="Fail"
#     else:
#         Column_Match_Flag = "Pass"
#         Sequence_Match_Flag="Pass"

#     PreSchema_Checked = bigdata.loc[bigdata['Data_Type_Match'] == 'False'] 
#     PreSchema_Checked1 = bigdata.loc[bigdata['Column_Match'] == 'False'] 
#     PreSchema_Checked2 = bigdata.loc[bigdata['SequenceMatch'] == 'False'] 
   
#     Rule_Summary.loc['0'] = ['NA', 'Precheck-1', 'Precheck-Schema', Column_Match_Flag,'NA','NA','NA','NA',Sequence_Match_Flag]
#     Rule_Summary.loc['1'] = ['NA', 'Precheck-2', 'Precheck-Datatype', Data_Type_Match_Flag,'NA','NA',Data_Type_Match_Flag,'NA','NA']
    
    
#     if "Fail" == Data_Type_Match_Flag or "Fail" == Column_Match_Flag:
#         fileName = "Report_" + subject + "_" + date + ".csv"
#         Rule_Summary.to_csv(reportOutputDir + fileName, index=False)
#         #dbutils.notebook.exit("Primary checks failed. Stop Execution")

#     errFileName = "Error_" + subject + "_" + date + ".csv"

#     err_out_df = pd.DataFrame()
    
#     for rule in rules:
#         # if rule["ValidationOperator"] == 'None': 
#         #     continue
#         # else:
#             #print(rule["DataAttribute"], rule["RuleID"], rule["ValidationOperator"], rule["ValueToBeMatch"])
          
#             Orignal_Datatype = check_dtype(csvdf,rule["DataAttribute"])
#            #if Column_Match_Flag == "Pass":
#             var = check_ruleValidation(csvdf, rule["DataAttribute"], rule["RuleID"], rule["ValidationOperator"],
#                                        rule["ValueToBeMatch"], errorOutputDir,errFileName)
#             'RuleId', 'RuleName',  'ColumnName', 'Validation_Result','errorOutputDir','errFileName'
            
#             if Orignal_Datatype==rule["DataType"] :
#                 Datatype_Match_flag="True"
#             else:
#                 Datatype_Match_flag="False"
#             # if df_rdf['CsvSequence'].all()== df_rdf['Sequence'].all() :
#             #     SequenceMatch_flag="True"
#             # else:
#             #     SequenceMatch_flag="False"        
            
            
#             df = { 'RuleId': rule["RuleID"], 'RuleName': rule["RuleName"],
#                    'ColumnName': rule["DataAttribute"],'ValidationOperator':rule["ValidationOperator"],'Datatype_RuleFile': rule["DataType"],'Datatype_OrignalFile':Orignal_Datatype,'Datatype_Match':Datatype_Match_flag,'RuleSequence': rule["Sequence"],'SequenceMatch':'', 'Validation_Result': var}
            
#             df=pd.DataFrame.from_dict(df, orient='index').transpose()
            
            
#             Rule_Summary = pd.concat([Rule_Summary, df]).reset_index(drop=True)
    
#     cols_index.insert(0,'NA')
#     cols_index.insert(1,'NA')
    
#     if len(Rule_Summary['RuleId'])==len(cols_index):
#         Rule_Summary['Orignalsequence']=cols_index
#         Rule_Summary['Orignalsequence'] = Rule_Summary['Orignalsequence'].astype(str)
#     else:
#         rule_length = len(Rule_Summary['RuleId'])
#         original_length = len(cols_index)
#         while original_length < rule_length:
#             cols_index.append('NA')
#             original_length +=1
        
                    
#     Rule_Summary['Orignalsequence']=cols_index
#     Rule_Summary['Orignalsequence'] = Rule_Summary['Orignalsequence'].astype(str)
        
#     Rule_Summary['SequenceMatch'] = np.where((Rule_Summary['Orignalsequence'].astype(str) == Rule_Summary['RuleSequence'].astype(str)), 'True', 'False')
#     Rule_Summary.loc[1]['SequenceMatch']="NA"


#     if "False" in list(Rule_Summary['SequenceMatch']):
#         Rule_Summary.loc[0]['SequenceMatch']="False"
#         Rule_Summary.loc[0]['ValidationOperator']="NA"
#         Rule_Summary.loc[1]['ValidationOperator']="NA"
        
#     else:
#         Rule_Summary.loc[0]['SequenceMatch']="True"
#         Rule_Summary.loc[0]['ValidationOperator']="NA"
#         Rule_Summary.loc[1]['ValidationOperator']="NA"
    

    
            
#     html_table = PreSchema_Checked.to_html(index=False, header=True, index_names=False) 
#     html_table1 = PreSchema_Checked1.to_html(index=False, header=True, index_names=False) 
#     html_table2 = PreSchema_Checked2.to_html(index=False, header=True, index_names=False) 
#     fileName = "Report_" + subject + "_" + date + ".csv"
#     Rule_Summary.to_csv( reportOutputDir + fileName, index=False)

    

#     if  Rule_Summary["Validation_Result"][1] =="Fail" or Rule_Summary["Validation_Result"][0] =="Fail":
#         isRuleValidationPass="False"
#         ruleValidation_dict=Rule_Summary.to_dict('records')
#     else:
#         isRuleValidationPass="True"
#         ruleValidation_dict=Rule_Summary.to_dict('records')


#     if  Rule_Summary["Datatype_Match"][1] =="Fail" :    
#         isDatatypeValidationPass="False"
#         datatypeValidation_dict=PreSchema_Checked.to_dict('records')
#     else:
#         isDatatypeValidationPass="True"
#         datatypeValidation_dict=PreSchema_Checked.to_dict('records')


#     if  Rule_Summary["SequenceMatch"][0] =="False" :        
#         isSchemaValidationPass="False"
#         schemaValidation_dict=PreSchema_Checked1.to_dict('records')
#         schemaValidation_dict=PreSchema_Checked2.to_dict('records')
#     else:
#         isSchemaValidationPass="True"
#         schemaValidation_dict=PreSchema_Checked2.to_dict('records')

    
#     json_object = []

#     data = {'isRuleValidationPass':isRuleValidationPass,'ruleValidation':ruleValidation_dict ,'isSchemaValidationPass':isSchemaValidationPass,'schemaValidation': schemaValidation_dict,'isDatatypeValidationPass':isDatatypeValidationPass,'DatatypeValidation':datatypeValidation_dict}
    
#     json_object.append(data)
        
#     with open ('report.json','w') as f:
#         f.write(json.dumps(json_object,indent=4))              
      

#     rs_rows,rs_columns=Rule_Summary.shape
#     #Write the same report csv as html file
#     fileName = "Report_" + subject + "_" + date + ".html"
#     html = Rule_Summary.to_html()
#     html = f"<html><body>{html}<h4>Total number of rows in Csv={no_of_rows}<br>Total number of columns in Csv={no_of_columns}</h4><br></body></html>"
#     if Rule_Summary["Datatype_Match"][1] =="Fail"  :
#         html = f"<html><body>{html}<br><table>{html_table}</table><br></body></html>"
#     # if "Fail" == Column_Match_Flag :
#     #     html = f"<html><body>{html}<br><table>{html_table1}</table><br></body></html>"
#     if Rule_Summary["SequenceMatch"][0] =="False":
#         html = f"<html><body>{html}<br><table>{html_table2}</table><br></body></html>"

#     filePath =  reportOutputDir
#     text_file = open(filePath + fileName, "w")
#     text_file.write(html)
#     text_file.close()

#     stage_file = errorOutputDir+errFileName
#     df = pd.read_csv(stage_file)
#     df.drop_duplicates().to_csv( errorOutputDir + errFileName, index=False)
#     print("Rwlesummary\n",Rule_Summary)




# run_driver()


# Databricks notebook source
import json
import pandas as pd
import numpy as np
from datetime import datetime
import configparser
import os

# MAGIC %run /Shared/DFP/RuleEngine/RuleEngineDev/CleanupFiles

# COMMAND ----------

# MAGIC %run /Shared/DFP/RuleEngine/RuleEngineDev/QueryBuilder

# COMMAND ----------

# MAGIC %run /Shared/DFP/RuleEngine/RuleEngineDev/JsonParser

# COMMAND ----------

# MAGIC %run /Shared/DFP/RuleEngine/RuleEngineDev/CsvParser

# COMMAND ----------

# MAGIC %run /Shared/DFP/RuleEngine/RuleEngineDev/Utility

# COMMAND ----------

# fileName geting from ADF pipeline

from CsvParser import getDFfromCsv, getDFfromXlsxMerge, getDFfromXls, check_dtype, check_ruleValidation,getDFfromXlsx
from JsonParser import GetAllValueByKey, GetRules
from Utility import getUniqueValueList, list_contains

# data= '{"RuleID": "10","RuleName": "ValidData_1.csv_email validation","DataAttribute": "email","DataType": "String","ValidationOperator": "Regular Expression","ValueToBeMatch": "","Order": "10","DataObject": "table","DataSource": "ValidData_1.csv","Sequence": "10"}'
# def run_driver(request):
def run_driver():
    # request = json.loads(request)
    # configFilePathCntnr = request.get("DataSource")
    # print("configpath =>>>>",configFilePathCntnr)

    # COMMAND ----------

    # Read the App configuraiton ruleEngineConfiguraitonXls.ini
    # mountPath = '/dbfs/mnt'
    # mountPathXlsx = 'dbfs:/mnt'
    #configFilePath = configFilePathCntnr
    configFilePath= "configuration.ini"
    # stage_dir = "/dbfs/mnt/sgre-apps/data_validation_engine/"
    subject = 'Data_Validation'
    parser = configparser.ConfigParser()
    parser.read(configFilePath)

    #ruleFilePath = request.get('RULE_FILE_PATH')
    ruleFilePath=parser.get('APP', 'RULE_FILE_PATH')
    Column_address=parser.get('SOURCE', 'COLUMN_ADDRESS')
    Column_address1=parser.get('SOURCE', 'COLUMN_ADDRESS1')
    sheet_name=parser.get('SOURCE', 'sheet_name')

    print(Column_address)
    
    print("rule file path",ruleFilePath)
    outputDir = parser.get('APP', 'OUTPUT_FILE_PATH')
    reportOutputDir = outputDir + '/report/'
    errorOutputDir = outputDir + '/error/'
    rules = GetRules(ruleFilePath)
    print("Total rules in the rule file - ", len(rules))

    date = datetime.now().strftime("%Y%m%d_%I%M%S")
    TablesName = GetAllValueByKey(rules, "DataObject")
    TableList = getUniqueValueList(TablesName)

    # Data type validatoin
    sysValidDataTypeList = ['int', 'string', 'bool', 'float']
    temp = GetAllValueByKey(rules, "DataType")
    dataTypeList = getUniqueValueList(temp)
    dataTypeValidation = list_contains(sysValidDataTypeList, dataTypeList)
    print("Data type in rule file is valid - " + str(dataTypeValidation))

    # Operator validation
    sysValOperatorList = ['regex', 'reference', 'notnull', ]
    temp = GetAllValueByKey(rules, "ValidationOperator")
    operatorList = getUniqueValueList(temp)
    operatorValidator = list_contains(sysValOperatorList, operatorList)
    print("Operator validation in rule file is valid - " + str(operatorValidator))

    SOURCE_TYPE = parser.get('APP', 'SOURCE_TYPE')
    SOURCE_DATA_FILE_PATH = parser.get('SOURCE', 'SOURCE_DATA_FILE_PATH')
    SOURCE_DATA_FILE_PATH_XLS =  parser.get('SOURCE', 'SOURCE_DATA_FILE_PATH')
    SKIP_ROWS = parser.get('SOURCE', 'SKIP_ROWS')

    csvdf = pd.DataFrame()
    # Read the CSV
    if SOURCE_TYPE == 'CSV':
        csvdf = getDFfromCsv(SOURCE_DATA_FILE_PATH, SKIP_ROWS) 
        no_of_rows,no_of_columns=csvdf.shape   


    # Read the XLS
    if SOURCE_TYPE == 'XLS':
        csvdf = getDFfromXls(SOURCE_DATA_FILE_PATH, SKIP_ROWS)
        no_of_rows,no_of_columns=csvdf.shape

    # Read the XLSX
    if SOURCE_TYPE == 'XLSX':
        #csvdf = getDFfromXlsxMerge(SOURCE_DATA_FILE_PATH, SKIP_ROWS)
        csvdf= getDFfromXlsx(SOURCE_DATA_FILE_PATH, sheet_name,Column_address,Column_address1,SKIP_ROWS)
        no_of_rows,no_of_columns=csvdf.shape
       
        

    dtp = []
    for colName in csvdf.columns.tolist():
        dtp.append(check_dtype(csvdf, colName))

    ruleColList = GetAllValueByKey(rules, "DataAttribute")
    ruleColList = getUniqueValueList(ruleColList)

    csvColList = csvdf.columns
    csvColList = getUniqueValueList(csvColList)   

    csvcolValidator = list_contains(ruleColList, csvColList)
    rulcolValidator = list_contains(csvColList, ruleColList)

    df_rule = pd.DataFrame(rules)
    df_rdf = pd.DataFrame()
    df_rdf = df_rule[['RuleID', 'Sequence' ,'DataAttribute', 'DataType']]
    df_rdf = df_rdf.loc[df_rdf['Sequence'].notna()]
    df_rdf.sort_values(by=['Sequence'], ascending=False)
    df_rdf = df_rdf.drop_duplicates(['DataAttribute', 'DataType'], keep='first').reset_index(drop=True)
    df_csv = pd.DataFrame(list(zip(csvColList, dtp)),columns=['CSV_Col_Name', 'CsvDataType'])
    cols_index = [(csvdf.columns.get_loc(col)+1) for col in csvColList]
    df_rdf = df_rdf.assign(CsvSequence = cols_index)
    df_rdf['CsvSequence'] = df_rdf['CsvSequence'].astype(str)
    
    bigdata = pd.concat([df_rdf, df_csv], axis=1).reindex(df_rdf.index)
    
    bigdata['CsvDataType'] = np.where(bigdata['CsvDataType'] == 'pass', bigdata['DataType'], bigdata['CsvDataType'])
    # print(bigdata['CsvDataType']) 
    bigdata['CsvDataType'] = np.where(bigdata['DataType'] == 'date', bigdata['DataType'], bigdata['CsvDataType'])

    bigdata['Data_Type_Match'] = np.where(bigdata['DataType'] == bigdata['CsvDataType'], 'True', 'False')
    
   
    bigdata['Column_Match'] = np.where(df_rdf['DataAttribute'] == bigdata['CSV_Col_Name'], 'True', 'False')
    
    bigdata['SequenceMatch'] = np.where(df_rdf['CsvSequence']== df_rdf['Sequence'], 'True', 'False')
    
    
    # Write bigdata dataframe to a csv
    Rule_Summary = pd.DataFrame(columns=['RuleId', 'RuleName',  'ColumnName', 'Validation_Result','Datatype_RuleFile','Datatype_OrignalFile','Datatype_Match','RuleSequence','SequenceMatch'])
                       

    if "False" in list(bigdata['Data_Type_Match']) :
        Data_Type_Match_Flag = "Fail"
    else:
        Data_Type_Match_Flag = "Pass"

    if "False" in list(bigdata['Column_Match']) or "False" in list(bigdata['SequenceMatch']):
        Column_Match_Flag = "Fail"
        Sequence_Match_Flag="Fail"
    else:
        Column_Match_Flag = "Pass"
        Sequence_Match_Flag="Pass"

    PreSchema_Checked = bigdata.loc[bigdata['Data_Type_Match'] == 'False'] 
    PreSchema_Checked1 = bigdata.loc[bigdata['Column_Match'] == 'False'] 
    PreSchema_Checked2 = bigdata.loc[bigdata['SequenceMatch'] == 'False'] 
   
    Rule_Summary.loc['0'] = ['NA', 'Precheck-1', 'Precheck-Schema', Column_Match_Flag,'NA','NA','NA','NA',Sequence_Match_Flag]
    Rule_Summary.loc['1'] = ['NA', 'Precheck-2', 'Precheck-Datatype', Data_Type_Match_Flag,'NA','NA',Data_Type_Match_Flag,'NA','NA']
    
    
    if "Fail" == Data_Type_Match_Flag or "Fail" == Column_Match_Flag:
        fileName = "Report_" + subject + "_" + date + ".csv"
        Rule_Summary.to_csv(reportOutputDir + fileName, index=False)
        #dbutils.notebook.exit("Primary checks failed. Stop Execution")

    errFileName = "Error_" + subject + "_" + date + ".csv"

    err_out_df = pd.DataFrame()
    
    for rule in rules:
        # if rule["ValidationOperator"] == 'None': 
        #     continue
        # else:
            #print(rule["DataAttribute"], rule["RuleID"], rule["ValidationOperator"], rule["ValueToBeMatch"])
          
            Orignal_Datatype = check_dtype(csvdf,rule["DataAttribute"])
           #if Column_Match_Flag == "Pass":
            var = check_ruleValidation(csvdf, rule["DataAttribute"], rule["RuleID"], rule["ValidationOperator"],
                                       rule["ValueToBeMatch"])
            'RuleId', 'RuleName',  'ColumnName', 'Validation_Result'
            
            if Orignal_Datatype==rule["DataType"] :
                Datatype_Match_flag="True"
            else:
                Datatype_Match_flag="False"
            # if df_rdf['CsvSequence'].all()== df_rdf['Sequence'].all() :
            #     SequenceMatch_flag="True"
            # else:
            #     SequenceMatch_flag="False"        
            
            
            df = { 'RuleId': rule["RuleID"], 'RuleName': rule["RuleName"],
                   'ColumnName': rule["DataAttribute"],'ValidationOperator':rule["ValidationOperator"],'Datatype_RuleFile': rule["DataType"],'Datatype_OrignalFile':Orignal_Datatype,'Datatype_Match':Datatype_Match_flag,'RuleSequence': rule["Sequence"],'SequenceMatch':'', 'Validation_Result': var}
            
            df=pd.DataFrame.from_dict(df, orient='index').transpose()
            
            
            Rule_Summary = pd.concat([Rule_Summary, df]).reset_index(drop=True)
    
    cols_index.insert(0,'NA')
    cols_index.insert(1,'NA')
    
    if len(Rule_Summary['RuleId'])==len(cols_index):
        Rule_Summary['Orignalsequence']=cols_index
        Rule_Summary['Orignalsequence'] = Rule_Summary['Orignalsequence'].astype(str)
    else:
        rule_length = len(Rule_Summary['RuleId'])
        original_length = len(cols_index)
        while original_length < rule_length:
            cols_index.append('NA')
            original_length +=1
        
                    
    Rule_Summary['Orignalsequence']=cols_index
    Rule_Summary['Orignalsequence'] = Rule_Summary['Orignalsequence'].astype(str)
        
    Rule_Summary['SequenceMatch'] = np.where((Rule_Summary['Orignalsequence'].astype(str) == Rule_Summary['RuleSequence'].astype(str)), 'True', 'False')
    Rule_Summary.loc[1]['SequenceMatch']="NA"


    if "False" in list(Rule_Summary['SequenceMatch']):
        Rule_Summary.loc[0]['SequenceMatch']="False"
        Rule_Summary.loc[0]['ValidationOperator']="NA"
        Rule_Summary.loc[1]['ValidationOperator']="NA"
        
    else:
        Rule_Summary.loc[0]['SequenceMatch']="True"
        Rule_Summary.loc[0]['ValidationOperator']="NA"
        Rule_Summary.loc[1]['ValidationOperator']="NA"
    

    
            
    html_table = PreSchema_Checked.to_html(index=False, header=True, index_names=False) 
    html_table1 = PreSchema_Checked1.to_html(index=False, header=True, index_names=False) 
    html_table2 = PreSchema_Checked2.to_html(index=False, header=True, index_names=False) 
    fileName = "Report_" + subject + "_" + date + ".csv"
    Rule_Summary.to_csv( reportOutputDir + fileName, index=False)

    

    if  Rule_Summary["Validation_Result"][1] =="Fail" or Rule_Summary["Validation_Result"][0] =="Fail":
        isRuleValidationPass="False"
        ruleValidation_dict=Rule_Summary.to_dict('records')
    else:
        isRuleValidationPass="True"
        ruleValidation_dict=Rule_Summary.to_dict('records')


    if  Rule_Summary["Datatype_Match"][1] =="Fail" :    
        isDatatypeValidationPass="False"
        datatypeValidation_dict=PreSchema_Checked.to_dict('records')
    else:
        isDatatypeValidationPass="True"
        datatypeValidation_dict=PreSchema_Checked.to_dict('records')


    if  Rule_Summary["SequenceMatch"][0] =="False" :        
        isSchemaValidationPass="False"
        schemaValidation_dict=PreSchema_Checked1.to_dict('records')
        schemaValidation_dict=PreSchema_Checked2.to_dict('records')
    else:
        isSchemaValidationPass="True"
        schemaValidation_dict=PreSchema_Checked2.to_dict('records')

    
    json_object = []

    data = {'isRuleValidationPass':isRuleValidationPass,'ruleValidation':ruleValidation_dict ,'isSchemaValidationPass':isSchemaValidationPass,'schemaValidation': schemaValidation_dict,'isDatatypeValidationPass':isDatatypeValidationPass,'DatatypeValidation':datatypeValidation_dict}
    
    json_object.append(data)
        
    with open ('report.json','w') as f:
        f.write(json.dumps(json_object,indent=4))              
      

    rs_rows,rs_columns=Rule_Summary.shape
    #Write the same report csv as html file
    fileName = "Report_" + subject + "_" + date + ".html"
    html = Rule_Summary.to_html()
    html = f"<html><body>{html}<h4>Total number of rows in Csv={no_of_rows}<br>Total number of columns in Csv={no_of_columns}</h4><br></body></html>"
    if Rule_Summary["Datatype_Match"][1] =="Fail"  :
        html = f"<html><body>{html}<br><table>{html_table}</table><br></body></html>"
    # if "Fail" == Column_Match_Flag :
    #     html = f"<html><body>{html}<br><table>{html_table1}</table><br></body></html>"
    if Rule_Summary["SequenceMatch"][0] =="False":
        html = f"<html><body>{html}<br><table>{html_table2}</table><br></body></html>"

    filePath =  reportOutputDir
    text_file = open(filePath + fileName, "w")
    text_file.write(html)
    text_file.close()

    stage_file =  "C:/rulengine_master/Report/error/error_Log.csv"
    df = pd.read_csv(stage_file)
    df.drop_duplicates().to_csv( errorOutputDir + errFileName, index=False)
    print("Rwlesummary\n",Rule_Summary)



run_driver()