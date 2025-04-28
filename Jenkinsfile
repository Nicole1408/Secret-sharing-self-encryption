pipeline {
    agent {
        node {
            label 'Agent01'
        }
    }
    stages{
        stage("Deployment"){
       	    steps {
               withKubeConfig([credentialsId: 'K8s-config-file' , serverUrl: 'https://167.235.66.115:6443', namespace:'sedss']) {
                 sh 'kubectl apply -f rest-api-deployment.yml'
                 sh 'kubectl get pods'
               }
 
            }
        }
    }
}