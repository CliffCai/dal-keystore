/*
   Copyright 2018 Intel Corporation

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
*/

#define __STDC_WANT_LIB_EXT1__ 1

#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "base64.h"

#include "jhi.h"
#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/tree.h>

#define MAX_APPLET_BLOB_SIZE 30000
#define XML_ELEMT_NAME_BLOB "appletBlob"
#define XML_ELEMT_NAME_APP_LIST "applets"
#define XML_ELEMT_NAME_APP "applet"
#define XML_ELEMT_NAME_APP_DAL_PATH "appletDalpPath"
#define XML_ELEMT_NAME_APP_PACK_PATH "appletPackPath"
#define XML_ELEMT_NAME_APP_ID "appletId"

#define JHI_INIT_ONLY_ARG "--jhi_init_only"

#define JHI_CHECK_COUNT 10
#define JHI_WAIT_SEC 1
#define MISSING_CONFIG_FILE -3
#define RET_SUCCESS 0

typedef unsigned char uint8_t;

using namespace std;

xmlNode *find_element(xmlNode *a_node, const char *xml_element_name)
{
    xmlNode *cur_node = NULL, *ret;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next)
    {
        if (cur_node->type == XML_ELEMENT_NODE)
        {
            if (!strcmp((const char *)(cur_node->name), xml_element_name))
                return cur_node;
        }

        ret = find_element(cur_node->children, xml_element_name);
        if (ret)
            return ret;
    }

    return NULL;
}

xmlChar *get_content(xmlNode *a_node, const char *xml_element_name)
{
    xmlNode *node = NULL;
    xmlChar *p = NULL;

    if (!a_node || !xml_element_name)
        return NULL;

    node = find_element(a_node, xml_element_name);
    if (!node)
        return NULL;

    p = xmlNodeGetContent(node);
    return p;
}

char *get_pack_file(char *xml_file_name, size_t *out_len)
{
    LIBXML_TEST_VERSION
    /*parse the file and get the DOM */

    if (!xml_file_name || !out_len)
        return NULL;

    xmlDoc *doc = xmlReadFile(xml_file_name, NULL, 0);
    if (!doc)
    {
        xmlCleanupParser();
        return NULL;
    }

    xmlNode *root_element = NULL;
    root_element = xmlDocGetRootElement(doc);
    if (!root_element)
    {
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return NULL;
    }

    xmlChar *p = get_content(root_element, XML_ELEMT_NAME_BLOB);
    if (!p)
    {
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return NULL;
    }

    size_t inLen = strlen((char *)p);
    char *out = NULL;
    if (inLen > MAX_APPLET_BLOB_SIZE)
        printf("Applet BLOB content in: %s, is too big: %d Bytes! MAX_APPLET_BLOB_SIZE is: \n", xml_file_name, MAX_APPLET_BLOB_SIZE);
    else {
        if (!base64_decode_alloc((char *)p, inLen, &out, out_len))
            printf("Error during decoding base64 buffer\n");
    }

    xmlFree(p);
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return out;
}

struct applet_obj
{
    string dalp_file_path;
    string pack_file_path;
    string app_id;

    applet_obj(const char *dalp_file_path_c_str, const char *pack_file_path_c_str, const char *app_id_c_str)
    {
        if (dalp_file_path_c_str)
            dalp_file_path = string(dalp_file_path_c_str);

        if (pack_file_path_c_str)
            pack_file_path = string(pack_file_path_c_str);

        if (app_id_c_str)
            app_id = string(app_id_c_str);
    }
};

vector<applet_obj> get_applet_list(const char *xml_config_file_path)
{
    vector<applet_obj> applets;

    LIBXML_TEST_VERSION

    if (!xml_config_file_path)
        return applets;

    /*parse the file and get the DOM */
    xmlDoc *doc = xmlReadFile(xml_config_file_path, NULL, 0);
    if (!doc)
    {
        xmlCleanupParser();
        return applets;
    }

    /*Get the root element node */
    xmlNode *root_element = xmlDocGetRootElement(doc);
    if (!root_element)
        return applets;

    xmlNode *applet_list_node = find_element(root_element, XML_ELEMT_NAME_APP_LIST);
    if (!applet_list_node)
        return applets;

    for (
        xmlNode *curr_applet = find_element(applet_list_node, XML_ELEMT_NAME_APP);
        curr_applet;
        curr_applet = find_element(curr_applet->next, XML_ELEMT_NAME_APP)
    )
    {
        applets.push_back(
            applet_obj(
                (char*)get_content(curr_applet, XML_ELEMT_NAME_APP_DAL_PATH),
                (char*)get_content(curr_applet, XML_ELEMT_NAME_APP_PACK_PATH),
                (char*)get_content(curr_applet, XML_ELEMT_NAME_APP_ID)
            )
        );
    }

    xmlFreeDoc(doc);
    xmlCleanupParser();

    return applets;
}

JHI_RET check_JHI()
{
    JHI_RET ret = JHI_UNKNOWN_ERROR;
    int i = 0;

    for (i=0; i<JHI_CHECK_COUNT; i++)
    {
        //Check if JHI is present on the platform if not don't do anything
        printf("Checking JHI status...\n");

        //Init the JHI
        JHI_HANDLE handle = NULL;
        ret = JHI_Initialize(&handle, NULL, 0);
        if (ret != JHI_SUCCESS)
        {
            printf("JHI not ready! JHI return code: %d...\n", ret);
            sleep(JHI_WAIT_SEC);
        }
        else
        {
            printf("JHI status OK\n");
            //Deinit the JHI
            ret = JHI_Deinit(handle);
            if (ret != JHI_SUCCESS)
                continue;
            else
                break;
        }
    }

    if (ret != JHI_SUCCESS)
        printf("All JHI_Initialize function calls failed!. Number of tests: %d\n", i);

    return ret;
}

size_t convert_dalp_file(const char *applet_in_file, const char *applet_out_file)
{
    if (!applet_in_file || !applet_out_file)
        return 0;

    size_t out_len = 0;
    char *p = get_pack_file((char*)applet_in_file, &out_len);
    if (p)
    {
        printf("applet_out_file: %s, out_len: %lu\n", applet_out_file, out_len);

        std::ofstream outfile (applet_out_file, std::ofstream::binary);
        if (outfile.is_open())
        {
            outfile.write (p, out_len);
            outfile.close();
        }

        free(p);
    }

    return out_len;
}

int main(int argc, char *argv[])
{
    printf("DAL KS Initializer START\n");

    char *config_file_name = NULL;

    if (argc < 2)
    {
        printf("Missing configuration file! Usage example: /usr/sbin/dal_ks_initd /etc/dal-ks-init/dal_ks_initd.conf [--jhi_init_only]\n");
        printf("DAL KS Initializer END\n");
        return MISSING_CONFIG_FILE;
    }
    else
    {
        if (argv[1] != NULL)
            config_file_name = argv[1];
    }

    JHI_RET jhi_ret = check_JHI();
    if (jhi_ret != JHI_SUCCESS)
    {
        printf("JHI_INIT failed! ret code: %d exiting\n", jhi_ret);
        return jhi_ret;
    }

    if (argv[2] && strncmp(argv[2], JHI_INIT_ONLY_ARG, strlen(JHI_INIT_ONLY_ARG)) == 0) {
        printf("Executed JHI initialization only.\n");
        printf("DAL KS Initializer END\n");
        return RET_SUCCESS;
    }

    //2. read configuration - which files should be installed
    vector<applet_obj> applet_list = get_applet_list(config_file_name);

    //prepare common JHI handle
    JHI_HANDLE handle = NULL;
    JHI_RET ret = JHI_Initialize(&handle, NULL, 0);
    if (ret != JHI_SUCCESS)
    {
        printf("Failed to initialize JHI: ret[hex] = %04x\n", ret);
        return ret;
    }

    //3. FOR EACH APPLET
    for(size_t i=0; i < applet_list.size(); i++)
    {
        //3a. check and convert dalp file
        if (!applet_list[i].pack_file_path.empty())
        {
            printf("Converting applet: %s => %s\n", applet_list[i].dalp_file_path.c_str(), applet_list[i].pack_file_path.c_str());
            convert_dalp_file(applet_list[i].dalp_file_path.c_str(), applet_list[i].pack_file_path.c_str());
        }

        //3b. install applet using JHI API
        printf("Installing applet: %s, APP_ID: %s\n", applet_list[i].dalp_file_path.c_str(), applet_list[i].app_id.c_str());
        ret = JHI_Install2(handle, applet_list[i].app_id.c_str(), applet_list[i].dalp_file_path.c_str());
        if (ret != JHI_SUCCESS)
        {
            printf("Failed to install applet: %s, ret[hex] = %04x, ret[int] = %d\n", applet_list[i].dalp_file_path.c_str(), ret, ret);
            return ret;
        }
    }

    //4. Deinit the JHI
    printf("Deinitalizing JHI...\n");
    ret = JHI_Deinit(handle);
    if (ret != JHI_SUCCESS)
    {
        printf("Failed to perform JHI deinitialization. Error: ret[hex] = %04x\n", ret);
        return ret;
    }

    printf("DAL KS Initializer END\n");

    return RET_SUCCESS;
}
