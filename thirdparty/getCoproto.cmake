
set(USER_NAME           )      
set(TOKEN               )      
set(GIT_REPOSITORY      "https://github.com/Visa-Research/coproto.git")
set(GIT_TAG             "6f5452d7898a754b9e5aee8a826282bf629d6079" )

set(CLONE_DIR "${OC_THIRDPARTY_CLONE_DIR}/coproto")
set(BUILD_DIR "${CLONE_DIR}/out/build/${OC_CONFIG}")
set(LOG_FILE  "${CMAKE_CURRENT_LIST_DIR}/log-coproto.txt")

include("${CMAKE_CURRENT_LIST_DIR}/fetch.cmake")
message("\n\nOC_CPP_VER=${OC_CPP_VER}\n\n")
if(NOT DEFINED FETCH_BOOST)
    set(COPROTO_FETCH_BOOST ${ENABLE_BOOST})
else()
    set(COPROTO_FETCH_BOOST ${FETCH_BOOST})
endif()
if(NOT coproto_FOUND)
    string (REPLACE ";" "%" CMAKE_PREFIX_PATH_STR "${CMAKE_PREFIX_PATH}")
    message("\n\nCMAKE_PREFIX_PATH_STR=${CMAKE_PREFIX_PATH_STR}\n\n")
    find_program(GIT git REQUIRED)
    set(DOWNLOAD_CMD  ${GIT} clone ${GIT_REPOSITORY})
    set(CHECKOUT_CMD  ${GIT} checkout ${GIT_TAG})
    set(CONFIGURE_CMD ${CMAKE_COMMAND} -S ${CLONE_DIR} -B ${BUILD_DIR} -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
                       "-DCMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH_STR}"
                       -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE} 
                       -DVERBOSE_FETCH=${VERBOSE_FETCH}
                       -DCOPROTO_FETCH_SPAN=ON
                       -DCOPROTO_FETCH_FUNCTION2=ON
                       -DCOPROTO_FETCH_MACORO=ON
                       -DCOPROTO_FETCH_BOOST=${COPROTO_FETCH_BOOST}
                       -DCOPROTO_ENABLE_BOOST=${ENABLE_BOOST}
                       -DCOPROTO_ENABLE_OPENSSL=${ENABLE_OPENSSL}
                       -DCOPROTO_CPP_VER=${CRYPTO_TOOLS_STD_VER}
                       -DCOPROTO_PIC=${OC_PIC}
                       -DCOPROTO_THIRDPARTY_CLONE_DIR=${OC_THIRDPARTY_CLONE_DIR}
                       )
    set(BUILD_CMD     ${CMAKE_COMMAND} --build ${BUILD_DIR} --config ${CMAKE_BUILD_TYPE})
    set(INSTALL_CMD   ${CMAKE_COMMAND} --install ${BUILD_DIR} --config ${CMAKE_BUILD_TYPE} --prefix ${OC_THIRDPARTY_INSTALL_PREFIX})


    message("============= Building coproto =============")
    if(NOT EXISTS ${CLONE_DIR})
        run(NAME "Cloning ${GIT_REPOSITORY}" CMD ${DOWNLOAD_CMD} WD ${OC_THIRDPARTY_CLONE_DIR})
    endif()

    run(NAME "Checkout ${GIT_TAG} " CMD ${CHECKOUT_CMD}  WD ${CLONE_DIR})
    run(NAME "Configure"       CMD ${CONFIGURE_CMD} WD ${CLONE_DIR})
    run(NAME "Build"           CMD ${BUILD_CMD}     WD ${CLONE_DIR})
    run(NAME "Install"         CMD ${INSTALL_CMD}   WD ${CLONE_DIR})

    message("log ${LOG_FILE}\n==========================================")
else()
    message("coproto already fetched.")
endif()

install(CODE "
    if(NOT CMAKE_INSTALL_PREFIX STREQUAL \"${OC_THIRDPARTY_INSTALL_PREFIX}\")
        execute_process(
            COMMAND ${SUDO} \${CMAKE_COMMAND} --install ${BUILD_DIR} --config ${CMAKE_BUILD_TYPE} --prefix \${CMAKE_INSTALL_PREFIX}
            WORKING_DIRECTORY ${CLONE_DIR}
            RESULT_VARIABLE RESULT
            COMMAND_ECHO STDOUT
        )
    endif()
")