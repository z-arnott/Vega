pipeline {
    agent any
 
    stages {
        stage('Build') {
            steps {
                echo 'Building..'
                withCredentials([file(credentialsId: 'env', variable: 'mySecretEnvFile')]){
                    sh 'cp $mySecretEnvFile $WORKSPACE'
                }
                sh 'npm install'
                sh 'npm run build'
            }
        }
        stage('Start') {
            steps {
                echo 'Starting server..'
                sh 'screen -d -m -S screen.npmStart npm start'
            }
        }
        stage('Test') {
            steps {
                echo 'Testing..'
                sh 'npm run test'
            }
        }
        stage('Stop') {
            steps {
                echo 'Exiting server..'
                sh 'killall -15 node'
            }
        }
    }
    post {
        // Clean after build
        always {
            cleanWs(cleanWhenNotBuilt: true,
                    deleteDirs: true,
                    disableDeferredWipeout: true,
                    notFailBuild: true,
                    patterns: [[pattern: '**/node_modules/', type: 'EXCLUDE']])
        }
    }
}


