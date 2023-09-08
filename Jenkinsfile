def giteeCommentHeader = "| Check Name | Build Result | Build Details |\n| --- | --- | --- |\n"
pipeline {
	agent {
        label 'build-docker-x86'
    }
	environment {
		GITEE_TOKEN = credentials("${token_id}")
		
	}
	
	// stages 
	stages {
		stage('Get gitee PR_ID') {
            steps {
                sh '''#!/bin/bash +xv
                test -f ci_tags.py && rm ci_tags.py*
                wget https://gitee.com/openeuler/infrastructure/raw/master/ci/tools/ci_tags.py
                python3 ci_tags.py $giteeTargetNamespace $giteeTargetRepoName $giteePullRequestIid $GITEE_TOKEN ATP
                '''
            }
        }
		stage('Update and install rust') {
			steps {
				sh '''#!/bin/bash
					# update repo
					sudo yum update 
					sudo yum install -y -q gcc cmake openssl openssl-devel protobuf-compiler git rsync
					export RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
					export RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup
					
					# install rustup package
					cd ${HOME} 
					curl https://sh.rustup.rs -sSf -o rustup.sh && sh ./rustup.sh -y
					source $HOME/.cargo/env && rustup update -- nightly
					
					# update cargo registry
					cat > $HOME/.cargo/config << EOF
					[source.crates-io]
					registry = "https://github.com/rust-lang/crates.io-index"
					replace-with = 'ustc'

					[source.ustc]
					registry = "https://mirrors.ustc.edu.cn/crates.io-index"

					[http]
					check-revoke = false
EOF
					cargo install cargo-audit
				'''
			}
		}
		stage('git merge branch') {
			steps {
				sh '''#!/bin/bash
				if [ -d "PR-$giteePullRequestIid" ]; then
					rm -rf PR-$giteePullRequestIid
				fi
				mkdir PR-$giteePullRequestIid && rsync -ar --exclude "PR-*" ./ PR-$giteePullRequestIid && cd PR-$giteePullRequestIid
				git checkout -b pr_$giteePullRequestIid
				git fetch origin pull/$giteePullRequestIid/head:master-$giteePullRequestIid			
				git merge --no-edit master-$giteePullRequestIid										
			'''
			}
		}	
		stage('cargo clippy') {
			steps {
				sh '''#!/bin/bash
				
				source $HOME/.cargo/env && cd PR-$giteePullRequestIid
				cargo clippy
				'''
			}
		}
		stage('cargo test') {
			steps {
				sh '''#!/bin/bash
				
				source $HOME/.cargo/env && cd PR-$giteePullRequestIid
				cargo test
				'''
			}
		}
		stage('cargo build') {
			steps {
				sh '''#!/bin/bash

				source $HOME/.cargo/env && cd PR-$giteePullRequestIid
				cargo build
				'''
			}
		}       
		stage('cargo audit') {
			steps {
				sh '''#!/bin/bash

				source $HOME/.cargo/env && cd PR-$giteePullRequestIid
				cargo audit -D warnings
				'''
			}
		}  
	}

	// post
	post {
		success {
            node('build-docker-x86') {
			script {
				comments = giteeCommentHeader + "| Infra Check | **success** :white_check_mark: | [#${currentBuild.fullDisplayName}](${env.BUILD_URL}/console) | \n"
				sh "python3 ../signatrust/ci_tags.py $giteeTargetNamespace $giteeTargetRepoName $giteePullRequestIid $GITEE_TOKEN ATS"
				}
			addGiteeMRComment comment: comments
			echo 'succeeded!'
            }   
		}
		failure {
            node('build-docker-x86') {
			script {
				comments = giteeCommentHeader + "| Infra Check | **failed** :x: | [#${currentBuild.fullDisplayName}](${env.BUILD_URL}/console) | \n"
				sh "python3 ../signatrust/ci_tags.py $giteeTargetNamespace $giteeTargetRepoName $giteePullRequestIid $GITEE_TOKEN ATF"
				}
			addGiteeMRComment comment: comments
			echo 'failed!'
            }
		}
	}
}
