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

// Function to handle POST request
void handle_post_request() {
    char query[MAX_QUERY_LENGTH];
    size_t content_length;
    char *action = NULL;
    struct json_object *param;
    struct json_object *response;
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

   if(strcmp(action,"Login")==0)
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
   }else if(!strcmp(action,"GetDHCP")){
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
