pipeline {
    agent any
    environment{
        CREDS = credentials('env')
    }
    stages {
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


