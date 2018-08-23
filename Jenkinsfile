pipeline {
  agent any
  stages {
    stage('checkout') {
      steps {
        git(url: 'https://github.com/harshith-pd/tool_temp.git', branch: '*', poll: true)
      }
    }
  }
}