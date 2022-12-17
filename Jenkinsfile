pipeline {
    agent any

    stages {
        withCredentials([file(credentialsId: 'env', variable: 'mySecretEnvFile')]){
            sh 'cp $mySecretEnvFile $WORKSPACE'
        }
        stage('build') {
            steps {
                echo 'Building..'
                sh 'npm install'
                sh 'npm run build'
                sh 'npm run prettier'
            }
        }
        stage('Test') {
            steps {
                echo 'Testing..'
                sh 'npm test'
            }
        }
    }
}


