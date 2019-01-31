CMAKE_MINIMUM_REQUIRED( VERSION 2.8.7 )
PROJECT(dal_ks_initd)

set(CMAKE_INSTALL_PREFIX /usr/sbin/)
#set(EXECUTABLE_OUTPUT_PATH out)

INCLUDE_DIRECTORIES(
inc
/usr/include/libxml2/
/usr/include/
)

AUX_SOURCE_DIRECTORY(src DIR_SRCS)

SET(INITD
${DIR_SRCS}
)

ADD_EXECUTABLE(dal_ks_initd ${INITD})

TARGET_LINK_LIBRARIES(dal_ks_initd jhi.so libxml2.so)
install(FILES dal_ks_initd DESTINATION ${CMAKE_INSTALL_PREFIX})
