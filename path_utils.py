import os

#set the working path
def set_working_path(args):
    args.workingPath = os.getcwd()

#set the storage path
def set_storage_path(args):
    args.storage = os.getcwd() + '/' + "storage"

#set the output path
def set_output_path(args):
    args.outputPath = os.getcwd()