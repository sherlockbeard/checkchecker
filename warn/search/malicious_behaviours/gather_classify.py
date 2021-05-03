import logging


def gather_classifed(apk_file):

    import sys
    sys.path.append("..")
    from train_and_test import classify

    result = []

    result.extend(classify(apk_file))

    new = ""
  
    # traverse in the string 
    for x in result:
        new += x 

    print('ANSWERRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR...')
    print(new)
    return new
