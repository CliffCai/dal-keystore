CMAKE_MINIMUM_REQUIRED( VERSION 2.8.7 )
PROJECT(keystore_applet)

set(CMAKE_INSTALL_PREFIX /usr/lib/dal/applets/)

install(FILES Keystore.dalp DESTINATION ${CMAKE_INSTALL_PREFIX})
