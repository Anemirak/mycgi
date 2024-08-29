#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#define MAX_QUERY_LENGTH 1024
#define MAX_BUFFER 512

const char *json_get_string_value_by_field(struct json_object *json, const char *p_field)  //获取字符串
{
    struct json_object *string_json = NULL;

    json_object_object_get_ex(json, p_field, &string_json);
    if (NULL == string_json)
    {
        printf("json_object_object_get error %s", p_field);
        return NULL;
    }

    if (json_type_string == json_object_get_type(string_json))
    {
        return json_object_get_string(string_json);
    }

    return NULL;
}

int json_get_int_value_by_field(struct json_object *json, const char *p_field)
{
    struct json_object *int_json = NULL;

    json_object_object_get_ex(json, p_field, &int_json);
    if (NULL == int_json)
    {
        printf("json_object_object_get error %s", p_field);
        return -1;
    }

    if (json_type_int == json_object_get_type(int_json))
    {
        return (int)json_object_get_int(int_json);
    }

    return -1;
}

const char *json_get_string_value(struct json_object *json)
{
    if (json_type_string == json_object_get_type(json))
    {
        return json_object_get_string(json);
    }

    return NULL;
}

struct json_object *json_get_json_object_by_field(struct json_object *json, const char *p_field)
{
    struct json_object *json_obj = NULL;

    json_object_object_get_ex(json, p_field, &json_obj);
    if (NULL == json_obj)
    {
        printf("json_object_object_get error %s", p_field);
        return NULL;
    }

    return json_obj;
}

int json_is_array(struct json_object *json)
{
    if (json_type_array == json_object_get_type(json))
    {
        return 0;
    }

    return -1;
}

int execute_command(const char *command, char *output, size_t output_size) {
    FILE *fp;
    char buffer[MAX_BUFFER];
    size_t bytes_read;

    // 确保传入的参数有效
    if (command == NULL || output == NULL || output_size == 0) {
        return -1;  // 返回错误码，表示参数无效
    }

    // 打开命令的管道
    fp = popen(command, "r");
    if (fp == NULL) {
        return -1;  // 返回错误码，表示无法执行命令
    }

    // 读取命令的输出
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        bytes_read = strnlen(buffer, sizeof(buffer));
        // 确保输出不会超出缓冲区大小
        if (bytes_read < output_size) {
            strncpy(output, buffer, output_size - 1);
            output[output_size - 1] = '\0';  // 确保输出缓冲区以 null 终止
        } else {
            // 如果输出太大，截断并确保缓冲区以 null 终止
            strncpy(output, buffer, output_size - 1);
            output[output_size - 1] = '\0';
        }
    } else {
        // 如果没有读取到数据，则清空输出缓冲区
        output[0] = '\0';
    }

    // 关闭管道
    pclose(fp);

    return 0;  // 返回 0 表示成功
}

// Function to get value from configuration file
int get_value_from_config(const char *file_path, const char *key, char *value, size_t value_size) {
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        perror("Error opening file");
        return -1;
    }

    char line[MAX_BUFFER];
    while (fgets(line, sizeof(line), file) != NULL) {
        char *key_start = strstr(line, key);
        if (key_start != NULL) {
            key_start += strlen(key);
            if (*key_start == '=') {
                key_start++;
                // Skip any leading spaces
                while (*key_start == ' ' || *key_start == '\t') {
                    key_start++;
                }

                // Remove trailing newline if present
                char *newline = strchr(key_start, '\n');
                if (newline) {
                    *newline = '\0';
                }

                // Remove surrounding quotes if present
                if (*key_start == '"') {
                    key_start++;
                    char *end_quote = strchr(key_start, '"');
                    if (end_quote) {
                        *end_quote = '\0';
                    }
                }

                // Copy the value into the buffer
                strncpy(value, key_start, value_size - 1);
                value[value_size - 1] = '\0'; // Ensure null-termination
                fclose(file);
                return 0;
            }
        }
    }

    fclose(file);
    fprintf(stderr, "Key not found\n");
    return -1;
}

// Function to handle POST request
void handle_post_request() {
    char query[MAX_QUERY_LENGTH];
    size_t content_length;
    char *action = NULL;
    struct json_object *param = NULL;
    struct json_object *response = NULL;
    struct json_object *wifiresponse = NULL;
    char *content_length_str = getenv("CONTENT_LENGTH");

    if (content_length_str == NULL) {
        printf("{\"error\":1,\"message\":\"Missing CONTENT_LENGTH\"}\n");
        return;
    }

    content_length = (size_t)atoi(content_length_str);
    if (content_length >= MAX_QUERY_LENGTH) {
        printf("{\"error\":1,\"message\":\"Request too large\"}\n");
        return;
    }

    // Read POST data
    fread(query, 1, content_length, stdin);
    query[content_length] = '\0'; // Null-terminate

    //{"ACT":"Login","param":{"admin":"admin","pwd":"12345678"}

   struct json_object *myjson = json_tokener_parse(query);
   action = json_get_string_value_by_field(myjson,"ACT");

   if(!strcmp(action,"Login"))
   {
        param = json_get_json_object_by_field(myjson,"param");
        char* admin = json_get_json_object_by_field(myjson,"admin");
        char* pwd = json_get_json_object_by_field(myjson,"pwd");
        if(!strcmp(admin, "admin") && !strcmp(pwd, "12345678"))
        {
            printf("{\"error\":0}\n");  //登录成功
        }else{
            printf("{\"error\":1,\"message\":\"admin or pwd error\"}\n");  //登录失败
        }
   }
   
   else if(!strcmp(action,"GetDHCP")){
        char ipaddr[MAX_BUFFER] = {0};
        char netmask[MAX_BUFFER] = {0};
        char start[MAX_BUFFER] = {0};
        char limit[MAX_BUFFER] = {0};
        char leasetime[MAX_BUFFER] = {0};
        execute_command("uci get network.lan.ipaddr", ipaddr, MAX_BUFFER);
        execute_command("uci get network.lan.netmask", netmask, MAX_BUFFER);
        execute_command("uci get dhcp.lan.start", start, MAX_BUFFER);
        execute_command("uci get dhcp.lan.limit", limit, MAX_BUFFER);
        execute_command("uci get dhcp.lan.leasetime", leasetime, MAX_BUFFER);
        response = json_object_new_object();
        json_object_object_add(response, "ipaddr", json_object_new_string(ipaddr));
        json_object_object_add(response, "netmask", json_object_new_string(netmask));
        json_object_object_add(response, "start", json_object_new_string(start));
        json_object_object_add(response, "limit", json_object_new_string(limit));
        json_object_object_add(response, "leasetime", json_object_new_string(leasetime));
        json_object_object_add(response, "error", json_object_new_int(0));
        printf("%s\n", json_object_to_json_string(response));
   }
   
   else if(!strcmp(action,"GetWIFI")){
        char device[MAX_BUFFER] = {0};
        char network[MAX_BUFFER] = {0};
        char mode[MAX_BUFFER] = {0};
        char ssid[MAX_BUFFER] = {0};
        execute_command("uci get wireless.@wifi-iface[0].device", device, MAX_BUFFER);
        execute_command("uci get wireless.@wifi-iface[0].network", network, MAX_BUFFER);
        execute_command("uci get wireless.@wifi-iface[0].mode", mode, MAX_BUFFER);
        execute_command("uci get wireless.@wifi-iface[0].ssid", ssid, MAX_BUFFER);
        wifiresponse = json_object_new_object();
        json_object_object_add(wifiresponse, "device", json_object_new_string(device));
        json_object_object_add(wifiresponse, "network", json_object_new_string(network));
        json_object_object_add(wifiresponse, "mode", json_object_new_string(mode));
        json_object_object_add(wifiresponse, "ssid", json_object_new_string(ssid));
        json_object_object_add(wifiresponse, "error", json_object_new_int(0));
        printf("%s\n", json_object_to_json_string(wifiresponse));
   }
   
   else if(!strcmp(action,"GetVersion")){
        char openwrt[MAX_BUFFER] = {0};
        char kernel[MAX_BUFFER] = {0};
        char fw_version[MAX_BUFFER] = {0};
        char full_fw_version[MAX_BUFFER] = {0};
        char vendor_askey_version[MAX_BUFFER] = {0};
        execute_command("cat /etc/openwrt_version", openwrt, MAX_BUFFER);
        execute_command("uname -r", kernel, MAX_BUFFER);
        get_value_from_config("/etc/system_version.info", "FW_VERSION", fw_version, MAX_BUFFER);
        get_value_from_config("/etc/system_version.info", "FULL_FW_VERSION", full_fw_version, MAX_BUFFER);
        get_value_from_config("/etc/system_version.info", "VENDOR_ASKEY_VERSION", vendor_askey_version, MAX_BUFFER);
        response = json_object_new_object();
        json_object_object_add(response, "openwrt", json_object_new_string(openwrt));
        json_object_object_add(response, "kernel", json_object_new_string(kernel));
        json_object_object_add(response, "fw_version", json_object_new_string(fw_version));
        json_object_object_add(response, "full_fw_version", json_object_new_string(full_fw_version));
        json_object_object_add(response, "vendor_askey_version", json_object_new_string(vendor_askey_version));
        json_object_object_add(response, "error", json_object_new_int(0));
        printf("%s\n", json_object_to_json_string(response));
   }
   
   else if(!strcmp(action,"GetDeviceInfo")){
        char device_manufacturer[MAX_BUFFER] = {0};
        char device_product[MAX_BUFFER] = {0};
        char device_revision[MAX_BUFFER] = {0};
        get_value_from_config("/etc/device_info", "DEVICE_MANUFACTURER", device_manufacturer, MAX_BUFFER);
        get_value_from_config("/etc/device_info", "DEVICE_PRODUCT", device_product, MAX_BUFFER);
        get_value_from_config("/etc/device_info", "DEVICE_REVISION", device_revision, MAX_BUFFER);
        response = json_object_new_object();
        json_object_object_add(response, "device_manufacturer", json_object_new_string(device_manufacturer));
        json_object_object_add(response, "device_product", json_object_new_string(device_product));
        json_object_object_add(response, "device_revision", json_object_new_string(device_revision));
        json_object_object_add(response, "error", json_object_new_int(0));
        printf("%s\n", json_object_to_json_string(response));
   }
   
   else if(!strcmp(action,"SetDHCP")){
        char cmd[MAX_BUFFER] = {0};
        int error = 0;
        char *ipaddr = json_get_string_value_by_field(myjson,"ipaddr");
        if(ipaddr == NULL){
            error = 1;
            printf("{\"error\":1, \"message\":\"ipaddr is missing\"}\n");
        }
        char *netmask = json_get_string_value_by_field(myjson,"netmask");
        if(netmask == NULL){
            error = 1;
            printf("{\"error\":1, \"message\":\"netmask is missing\"}\n");
        }
        char *start = json_get_string_value_by_field(myjson,"start");
        if(start == NULL){
            error = 1;
            printf("{\"error\":1, \"message\":\"start is missing\"}\n");
        }
        char *limit = json_get_string_value_by_field(myjson,"limit");
        if(limit == NULL){
            error = 1;
            printf("{\"error\":1, \"message\":\"limit is missing\"}\n");
        }
        char *leasetime = json_get_string_value_by_field(myjson,"leasetime");
        if(leasetime == NULL){
            error = 1;
            printf("{\"error\":1, \"message\":\"leasetime is missing\"}\n");
        }
        // uci set network.lan.ipaddr xx
        sprintf(cmd,"uci set network.lan.ipaddr=%s", ipaddr);
        system(cmd);

        memset(cmd,0,512);
        sprintf(cmd,"uci set network.lan.netmask=%s", netmask);
        system(cmd);

        memset(cmd,0,512);
        sprintf(cmd,"uci set network.lan.start=%s", start);
        system(cmd);

        memset(cmd,0,512);
        sprintf(cmd,"uci set network.lan.limit=%s", limit);
        system(cmd);

        memset(cmd,0,512);
        sprintf(cmd,"uci set network.lan.leasetime=%s", leasetime);
        system(cmd);

        system("uci commit");
        system("/etc/init.d/network restart");

        printf("{\"error\":%d}\n",error);
   }
   
   else if(!strcmp(action,"SetWIFI")){
        char cmd[MAX_BUFFER] = {0};
        int error = 0;
        char *device = json_get_string_value_by_field(myjson,"device");
        if(device == NULL){
            error = 1;
            printf("{\"error\":1, \"message\":\"device is missing\"}\n");
        }
        char *network = json_get_string_value_by_field(myjson,"network");
        if(network == NULL){
            error = 1;
            printf("{\"error\":1, \"message\":\"network is missing\"}\n");
        }
        char *mode = json_get_string_value_by_field(myjson,"mode");
        if(mode == NULL){
            error = 1;
            printf("{\"error\":1, \"message\":\"mode is missing\"}\n");
        }
        char *ssid = json_get_string_value_by_field(myjson,"ssid");
        if(ssid == NULL){
            error = 1;
            printf("{\"error\":1, \"message\":\"ssid is missing\"}\n");
        }

        // uci set network.lan.ipaddr xx
        sprintf(cmd,"uci set wireless.@wifi-iface[0].device=%s", device);
        system(cmd);

        memset(cmd,0,512);
        sprintf(cmd,"uci set wireless.@wifi-iface[0].network=%s", network);
        system(cmd);

        memset(cmd,0,512);
        sprintf(cmd,"uci set wireless.@wifi-iface[0].mode=%s", mode);
        system(cmd);

        memset(cmd,0,512);
        sprintf(cmd,"uci set wireless.@wifi-iface[0].ssid=%s", ssid);
        system(cmd);

        system("uci commit");
        system("/etc/init.d/network restart");

        printf("{\"error\":%d}\n",error);
   }

    if(wifiresponse != NULL){
        json_object_put(wifiresponse);  
    }
    if(response != NULL){
        json_object_put(response);  
    }
    if(response != NULL){
    json_object_put(param); 
    }  
    if(response != NULL){
    json_object_put(myjson); 
    } //清理操作
}

//{"ACT":"Login","param":{"admin":"admin","pwd":"12345678"}
int main() {
    // Check request method
    const char *method = getenv("REQUEST_METHOD");

    // Print HTTP header
    printf("Content-Type: application/json\n\n");

    if (method != NULL && strcmp(method, "POST") == 0) {
        handle_post_request();
    } else if (method != NULL && strcmp(method, "GET") == 0) {
        //handle_get_request();
        printf("{\"error\":1,\"message\":\"GET Method not supported\"}\n");
    } else {
        // Method not supported
        printf("{\"error\":1,\"message\":\"Method not supported\"}\n");
    }

    return 0;
}