CMAKE_MINIMUM_REQUIRED( VERSION 2.8.7 )
PROJECT(ks_lib)

# set release version
# IMPORTANT: Don't forget to update the specfile
set(BASE_VERSION_MAJOR 2)
set(BASE_VERSION_MINOR 3)
set(BASE_VERSION_REVISION 0)

#set(EXE_INSTALL_PREFIX /usr/sbin/)
#set(EXECUTABLE_OUTPUT_PATH out)
#set(LIBRARY_OUTPUT_PATH out)

add_definitions( 
  -DBASE_VERSION_MAJOR=${BASE_VERSION_MAJOR}
  -DBASE_VERSION_MINOR=${BASE_VERSION_MINOR}
  -DBASE_VERSION_REVISION=${BASE_VERSION_REVISION}
)

INCLUDE_DIRECTORIES(
inc
)

add_library(ias-security-keystore_lib_static STATIC 
	src/lib/IasKeystoreLib.cpp
	src/lib/ias_keystore.c	
)

add_executable(ksutil 
	src/util/ks_smoke.c
	src/util/ksutil.cpp
)

target_link_libraries(ksutil ias-security-keystore_lib_static)

install(FILES ksutil DESTINATION /usr/sbin/
PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_EXECUTE GROUP_READ)
install(FILES libias-security-keystore_lib_static.a DESTINATION /lib64/)
install(FILES inc/IasKeystoreLib.hpp DESTINATION /usr/include/)
