import pandas as pd
import numpy as np
import sklearn
import os
from sklearn.model_selection import train_test_split
from keras.layers import Input, Dense
from keras.models import Model, load_model
from dbn.tensorflow import SupervisedDBNClassification
from dbn.models import UnsupervisedDBN
from sklearn.svm import SVC, LinearSVC, NuSVR
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score
import matplotlib.pyplot as plt
from imports import *
from util import *
from Checkchecker import *  

data = PreProcess(DATASET_PATH)

benign_df = pd.read_csv('./csv/benign.csv')
malign_df = pd.read_csv('./csv/malign.csv')

# concatenating dataframe of benign and malign
frames = [benign_df,malign_df]
df = pd.concat(frames)
df.reset_index()
# Now df has the dataframe of features of all the apks 
#print(frames)
#print(df.values)

# dropping the first 2 columns as the first 2 columns are useless
df.drop(df.columns[[0, 0]], axis=1, inplace=True)
#print(df.values)
X = df.values
#print(X)
length = X.shape[0]
print(length)
print(X.shape[1])
y = [1]*(length//2) + [0]*(length//2)

print('Actual Dimensions of feature space is ', X.shape)

# splitting the data into training and testing set
X_train, X_test, Y_train, Y_test = train_test_split(X, y, train_size=0.8)

# Creating the auto-encoder 
if LOAD_MODEL:
    print('loading the encoder model...')
    loaded_encoder = load_model("pickled/autoEncoder.mod")
    loaded_encoder.compile(optimizer='adadelta', loss='categorical_crossentropy',metrics=['accuracy'])
else:
    encoding_dim = 1000  # dimension of the output
    # this is our input placeholder
    input_img = Input(shape=(X.shape[1],))
    # "encoded" is the encoded representation of the input
    encoded = Dense(encoding_dim, activation='relu')(input_img)
    # "decoded" is the lossy reconstruction of the input
    decoded = Dense(X.shape[1], activation='relu')(encoded)
    # this model maps an input to its reconstruction
    autoencoder = Model(input_img, decoded)

    autoencoder.compile(optimizer='adadelta', loss='categorical_crossentropy',metrics=['accuracy'])

    d= autoencoder.fit(
                    X_train, X_train,
                    epochs=34,
                    batch_size=5,
                    shuffle=True,
                    validation_data=(X_test, X_test)
                   )

    # saving the encoder with encoded as the output - we need this to readuce the dimension of the feature vector space
    our_encoder = Model(input_img, encoded)
    our_encoder.save('pickled/autoEncoder.mod')
    loaded_encoder = our_encoder
    print(d.history.keys())
    loss_train = d.history['loss']
    loss_val = d.history['val_loss']
    epochs = range(1,35)
    plt.plot(loss_train,'r-', label='loss')
    plt.plot(loss_val,'b-', label='val_loss')
    plt.title('Training and Validation loss')   
    plt.xlabel('Epochs')
    plt.ylabel('Loss')
    plt.legend()
    plt.savefig('foo.png')

# reducing the dimension of the feature vector space from (12*186) to (12*8)
X_with_reduced_dimension = loaded_encoder.predict(X)
print('Now the dimensions of the encoded input feature space is -- ' ,X_with_reduced_dimension.shape)

if not LOAD_MODEL:
    # Creating the classifier for the reduced dimension input to classify 
    # the Clasifier is a hybrid model which comprises of Unsupervised DBN followed by a SVM Classfier to predict the label
    svm = SVC()
    dbn = UnsupervisedDBN(hidden_layers_structure=[512, 256, 256, 512, 256],
                          batch_size=10,
                          learning_rate_rbm=0.06,
                          n_epochs_rbm=20,
                          activation_function='relu')
    classifier = Pipeline(steps=[('dbn', dbn),
                                 ('svm', svm)])

    ena = classifier.fit(X_with_reduced_dimension, y)

    f = open("pickled/DBNClassifier.pkl", "wb")
    pickle.dump(classifier, f)
    f.close()


f = open("pickled/DBNClassifier.pkl", "rb")
classifier = pickle.load(f)
f.close()

# X_train, X_test, Y_train, Y_test = train_test_split(X, y, train_size=0.8)
print("classification_report is ")
print(loaded_encoder.predict(X_test))
print(Y_test)
accc=accuracy_score(Y_test, classifier.predict(loaded_encoder.predict(X_test))) 
print(accc)
classification_report(Y_test, classifier.predict(loaded_encoder.predict(X_test)))
print("classification_report end")

def classify(apk):

    print('Analyzing APK -- ',os.path.basename(apk))
    print('-------------------------------------------------------------')
    a,d,dx = AnalyzeAPK(apk)
    feats = list()

    feats += (data.makeHotVector([data.vocabPerm.index(p) for p in a.get_permissions() if p in data.vocabPerm], \
                                    data.vocabLengths["perm"])).tolist()
    feats += (data.makeHotVector([data.vocabServ.index(p) for p in a.get_services() if p in data.vocabServ], \
                                    data.vocabLengths["serv"])).tolist()
    feats += (data.makeHotVector([data.vocabRecv.index(p) for p in a.get_receivers()if p in data.vocabRecv], \
                                    data.vocabLengths["recv"])).tolist()

    test_feats = np.array(feats)
    test_feats = test_feats.reshape((-1, 1))
    print('features of the test apk after is ',test_feats.T.shape)
    # print('Shape of the test apk features = ',test_feats.shape)

    loaded_encoder = load_model("pickled/autoEncoder.mod")
    loaded_encoder.compile(optimizer='adadelta', loss='categorical_crossentropy',metrics=['accuracy'])

    test_feats_with_reduced_dimension = loaded_encoder.predict(test_feats.T)
    print('Shape of the test apk features with readuced dimension = ',test_feats_with_reduced_dimension.shape)

    f = open("pickled/DBNClassifier.pkl", "rb")
    classifier = pickle.load(f)
    f.close()

    print('The hybrid model prediction =' ,classifier.predict(test_feats_with_reduced_dimension))

    if classifier.predict(test_feats_with_reduced_dimension) == [0]:
        return ('Malign')
    else:
        return ('Bengin')

print('-----------------------------------------------------------------------------------------------------')
print('Classifying APKs from ' + TEST_DATASET_PATH + ' folder.')
print('-----------------------------------------------------------------------------------------------------')
print('Given input is malware, predicting ')
#classify(parser.parse_args().input)

