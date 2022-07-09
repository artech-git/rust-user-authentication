#!/bin/bash

# env variables to prevent the logging of sensetive credentials
export HISTIGNORE='export DOPPLER_TOKEN*'
export HISTIGNORE='doppler*'

#insert the token into the doppler on that directory
echo ${DOPPLER_TOKEN} | doppler configure set token --scope ./

#insert the secret in the new  templates 
doppler secrets substitute settings-config.toml > settings.toml

rm ./settings-config.toml

#execute the build
./jwt 