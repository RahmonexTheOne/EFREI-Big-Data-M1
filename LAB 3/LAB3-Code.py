# Need to install packages with the command : pip install scikit-learn matplotlib

# Import necessary libraries
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt

# Step 1: Load the dataset
column_names = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", 
                "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", 
                "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", 
                "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", 
                "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", 
                "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", 
                "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", 
                "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", 
                "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", 
                "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"]

# Load the training and testing data
train_df = pd.read_csv('dataset_nsl-kdd/nsl-kdd/KDDTrain+.txt', header=None, names=column_names)
test_df = pd.read_csv('dataset_nsl-kdd/nsl-kdd/KDDTest+.txt', header=None, names=column_names)

# Step 2: Label encoding (convert 'normal' to 0, others to 1)
train_df['label'] = train_df['label'].apply(lambda x: 0 if x == 'normal' else 1)
test_df['label'] = test_df['label'].apply(lambda x: 0 if x == 'normal' else 1)

# Step 3: One-Hot Encode Categorical Variables ('protocol_type', 'service', 'flag')
# Apply One-Hot Encoding to categorical columns
train_df = pd.get_dummies(train_df, columns=['protocol_type', 'service', 'flag'])
test_df = pd.get_dummies(test_df, columns=['protocol_type', 'service', 'flag'])

# Ensure both train and test datasets have the same columns after One-Hot Encoding
train_df, test_df = train_df.align(test_df, join='left', axis=1, fill_value=0)

# Step 4: Feature scaling using StandardScaler
scaler = StandardScaler()
X_train = train_df.drop(columns=['label'])
y_train = train_df['label']
X_test = test_df.drop(columns=['label'])
y_test = test_df['label']

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Step 5: Train models and make predictions

# Logistic Regression Model
logreg_model = LogisticRegression(random_state=42, max_iter=1000)
logreg_model.fit(X_train_scaled, y_train)
y_pred_lr = logreg_model.predict(X_test_scaled)  # Predictions for Logistic Regression

# K-Nearest Neighbors (KNN) Model
knn_model = KNeighborsClassifier(n_neighbors=5)
knn_model.fit(X_train_scaled, y_train)
y_pred_knn = knn_model.predict(X_test_scaled)  # Predictions for KNN

# Multi-Layer Perceptron (MLP) Model
mlp_model = MLPClassifier(hidden_layer_sizes=(100,), max_iter=300, random_state=42)
mlp_model.fit(X_train_scaled, y_train)
y_pred_mlp = mlp_model.predict(X_test_scaled)  # Predictions for MLP

# Step 6: Model Evaluation - Accuracy, Precision, Recall, F1-Score

def evaluate_model(y_test, y_pred, model_name):
    """ Function to evaluate the performance of a model """
    print(f"=== {model_name} ===")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")
    print(f"Precision: {precision_score(y_test, y_pred):.2f}")
    print(f"Recall: {recall_score(y_test, y_pred):.2f}")
    print(f"F1-Score: {f1_score(y_test, y_pred):.2f}")
    print("\n")

# Evaluate Logistic Regression
evaluate_model(y_test, y_pred_lr, "Logistic Regression")

# Evaluate K-Nearest Neighbors (KNN)
evaluate_model(y_test, y_pred_knn, "K-Nearest Neighbors (KNN)")

# Evaluate Multi-Layer Perceptron (MLP)
evaluate_model(y_test, y_pred_mlp, "Multi-Layer Perceptron (MLP)")

# Step 7: Confusion Matrix Display for all models
def display_confusion_matrix(y_test, y_pred, model_name):
    """ Function to display the confusion matrix of a model """
    print(f"\n=== {model_name} Confusion Matrix ===")
    ConfusionMatrixDisplay.from_predictions(y_test, y_pred, display_labels=["Normal", "Anomaly"], cmap=plt.cm.Blues)
    plt.title(f'{model_name} - Confusion Matrix')
    plt.show()

# Display Confusion Matrices
display_confusion_matrix(y_test, y_pred_lr, "Logistic Regression")
display_confusion_matrix(y_test, y_pred_knn, "K-Nearest Neighbors (KNN)")
display_confusion_matrix(y_test, y_pred_mlp, "Multi-Layer Perceptron (MLP)")