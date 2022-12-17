pipeline {
    agent any
    
    stages {
        stage('build') {
            steps {
                echo 'Building..'
                withCredentials([file(credentialsId: 'env', variable: 'mySecretEnvFile')]){
                    sh 'cp $mySecretEnvFile $WORKSPACE'
                }
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


