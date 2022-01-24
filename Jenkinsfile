pipeline {
    options {
        timestamps()
	buildDiscarder(logRotator(daysToKeepStr: '7', artifactDaysToKeepStr: '7'))
	timeout(time: 100, unit: 'MINUTES')
        skipDefaultCheckout()
    }
  agent {
    label 'ND-CI-Ubuntu-20.04-dev'
    }
  environment {
        HTTP_PROXY='http://proxy-dmz.intel.com:912'
        HTTPS_PROXY='http://proxy-dmz.intel.com:912'
    }
  stages {
        stage('Clean workspace') {
            steps {
                cleanWs()
                }
            }
	 stage ('Build P4 SDE') {
             stages {
                stage("Clone P4 SDE repo") {
		    steps {
			 checkout([$class: 'GitSCM', branches: [[name: 'main']], 
		                    extensions: [
		                    [$class: 'RelativeTargetDirectory', relativeTargetDir: "p4_sde-nat-p4-driver"],
		                    [$class: 'CleanBeforeCheckout'],
		                ], 
		                userRemoteConfigs: [[credentialsId: '0b6d7f05-0d2f-469e-9ef7-a983c8b1c876', 
		                url: 'https://github.com/intel-innersource/networking.ethernet.acceleration.vswitch.p4-sde.p4-driver.git']]]) 
	                  }
	              }
	            stage("P4 SDE submodule update") {
                    	steps {
                            sh '''
                                #### workarround, as p4-sde submodule update failing due to teamforge permission issues ###
                           	cd $WORKSPACE/p4_sde-nat-p4-driver
                           	git checkout 36072f929f70165b01d71d40072a9bc285d7a6d5
                           	git submodule update --init --recursive
                         	'''
                        	}
	                }
                stage("Build P4 SDE for DPDK Target") {
                    steps {
                        sh '''
	      	            cd $WORKSPACE
	      	            mkdir install
		            export SDE=$PWD
		            export SDE_INSTALL=$SDE/install
              	            cd $SDE/p4_sde-nat-p4-driver
	      	            ./autogen.sh
	      	            ./configure --prefix=$SDE_INSTALL
		             cd $SDE/p4_sde-nat-p4-driver
		             make -j24
	      	             make install		
                        '''
                    }
                }       
            }
        }
        stage("Clone P4 OVS repo") {
		steps {
		     script {
			   if (env.CHANGE_BRANCH) {
				 CUR_BRANCH="${env.CHANGE_BRANCH}"
			    } else {
				 CUR_BRANCH="${env.BRANCH_NAME}"
			            }
			     }
			        checkout([$class: 'GitSCM', branches: [[name: "*/${CUR_BRANCH}"]], 
		                doGenerateSubmoduleConfigurations: false, 
		                extensions: [
		                    [$class: 'RelativeTargetDirectory', relativeTargetDir: "p4-ovs"],
		                    [$class: 'CloneOption', depth: 0, noTags: true, shallow: true],
		                    [$class: 'SubmoduleOption', recursiveSubmodules: true, parentCredentials: true],
		                    [$class: 'CleanBeforeCheckout'],
		                ], 
		                submoduleCfg: [], 
		                userRemoteConfigs: [[credentialsId: '0b6d7f05-0d2f-469e-9ef7-a983c8b1c876', 
		                url: 'https://github.com/intel-innersource/networking.ethernet.acceleration.vswitch.p4-ovs.ipdk-p4ovs.git']]]) 
	                }
	            }
        stage ("Build P4-OVS") {
            steps {
              sh '''
	      	 cd $WORKSPACE/p4-ovs
                 bash -c './install_dep_packages.sh $WORKSPACE/DEP_SRC'
	      	 bash -c 'source p4ovs_env_setup.sh $WORKSPACE/install && ./build-p4ovs.sh $WORKSPACE/install'
              '''
            }
        }
  }
  post {
      success { 
          echo "PASSED"
//           archiveArtifacts "p4-sde/${package_name}.tar.gz"
       }
   }
}
