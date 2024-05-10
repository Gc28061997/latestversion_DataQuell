import os
from datetime import datetime

def get_files_with_date(file_path):
    # Extracting date from the file name
    file_name = os.path.basename(file_path)
    file_date_str = file_name.split('_')[-1].split('.')[0]
    
    # Converting extracted date string to datetime object
    file_date = datetime.strptime(file_date_str, '%m%d%Y')
    
    # Getting the folder path from the file path
    file_folder = os.path.dirname(file_path)
    
    # Searching for files with the extracted date
    files = []
    for file_name in os.listdir(file_folder):
        if file_name.endswith('.csv'):
            file_base, ext = os.path.splitext(file_name)
            if len(file_base.split('_')) > 1:
                try:
                    file_date_from_name = datetime.strptime(file_base.split('_')[-1], '%m%d%Y')
                    if file_date_from_name == file_date:
                        files.append(file_name)  # Just appending file name without path
                except ValueError:
                    pass
    
    # Finding the most recent file
    most_recent_file = None
    if files:
        most_recent_file = max(files, key=lambda x: os.path.getmtime(os.path.join(file_folder, x)))
    
    return files, most_recent_file

# Get user input for file path containing the date
file_path = input("Enter the file path containing the date: ")

# Get the list of files with the extracted date and the most recent file
files_with_date, most_recent_file = get_files_with_date(file_path)

# Print files with date
print("Files with date:")
for file_name in files_with_date:
    print(os.path.basename(file_name))  # Print only file names without the full path

# Print the most recent file with date and time
if most_recent_file:
    print("Most recent file:", most_recent_file)
    # print("Date and time:", datetime.fromtimestamp(os.path.getmtime(os.path.join(os.path.dirname(file_path), most_recent_file))))
else:
    print("No files found with the provided date.")
