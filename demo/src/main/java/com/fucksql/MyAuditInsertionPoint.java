/*
* Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
*
* This code may be used to extend the functionality of Burp Suite Community Edition
* and Burp Suite Professional, provided that this usage does not violate the
* license terms for those products.
*/

package com.fucksql;

import java.util.ArrayList;
import static java.util.Arrays.asList;
import java.util.List;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

class MyScanCheck implements ScanCheck {
    StringSimilarity similar = new StringSimilarity();
    private final MontoyaApi api;
    private String sleep_time;
    private String urlWhitelistText = "";
    private String paramWhitelistText = "";
    boolean EnableProjectFilterCheckBox = true;

    MyScanCheck(MontoyaApi api) {
        this.api = api;
        CustomPanel CustomPanel = new CustomPanel();
        api.userInterface().registerSuiteTab("SQL config", CustomPanel);
        CustomPanel.getConfirmButton().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sleep_time = CustomPanel.getPacketDelayField().getText();
                urlWhitelistText = CustomPanel.getUrlWhitelistArea().getText();
                paramWhitelistText = CustomPanel.getParamWhitelistArea().getText();
                EnableProjectFilterCheckBox = CustomPanel.getEnableProjectFilterCheckBox().isSelected();
            }
        });
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        return null;
    }

    public static boolean isNumericZidai(String str) {
        for (int i = 0; i < str.length(); i++) {
            if (!Character.isDigit(str.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    public void print(String str) {
        Logging logging = api.logging();
        logging.logToOutput(str);
    }

    public HttpRequestResponse sendrequest(HttpRequest request) {
        if (sleep_time != null && !sleep_time.trim().isEmpty()) {
            try {
                double sleepTimeValue = Double.parseDouble(sleep_time);
                if (sleepTimeValue > 0) {
                    Thread.sleep((int) (sleepTimeValue * 1000));
                }
            } catch (NumberFormatException | InterruptedException e) {
                e.printStackTrace();
            }
        }
        HttpRequestResponse requestresponse = api.http().sendRequest(request);
        return requestresponse;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        // print("1111111");
        if(baseRequestResponse.request().method().equals("OPTIONS")){
            return auditResult();
        }
        List<AuditIssue> auditIssueList = new ArrayList<>();
        List<ParsedHttpParameter> parameters = baseRequestResponse.request().parameters();
        String request_body = baseRequestResponse.request().bodyToString();
        String response_body = baseRequestResponse.response().bodyToString();
        Boolean is_urlencode = false;
        while (request_body.contains("%") && request_body.contains("22") && !request_body.contains("{\"")) {
            try {
                String request_body_decode = URLDecoder.decode(request_body, "UTF-8");
                // 如果解码结果与原字符串相同，说明无法再解码，退出循环
                if (request_body_decode.equals(request_body)) {
                    break;
                }
                // 更新 request_body 为解码结果
                request_body = request_body_decode;
                // 检查是否包含 JSON 特征，确认解码成功
                if (request_body_decode.contains("{\"") && !request_body_decode.contains("%")) {
                    is_urlencode = true;
                    break;
                }
            } catch (Exception e) {
                // 解码失败，退出循环
                break;
            }
        }
        
        // get or post
        if (EnableProjectFilterCheckBox) {
            // print("1111111");
            if (!api.scope().isInScope(baseRequestResponse.request().url())) {
                return auditResult();
            }
        }
        List<String> list = asList("myqcloud.com", ".3g2", ".3gp", ".7z", ".aac", ".abw", ".aif", ".aifc", ".aiff",
                ".arc", ".au", ".avi", ".azw", ".bin", ".bmp", ".bz", ".bz2", ".cmx", ".cod", ".csh", ".css", ".csv",
                ".doc", ".docx", ".eot", ".epub", ".gif", ".gz", ".ico", ".ics", ".ief", ".jar", ".jfif", ".jpe",
                ".jpeg", ".jpg", ".m3u", ".mid", ".midi", ".mp4", ".mjs", ".mp2", ".mp3", ".mpa", ".mpe", ".mpeg",
                ".mpg", ".mpkg", ".mpp", ".mpv2", ".odp", ".ods", ".odt", ".oga", ".ogv", ".ogx", ".otf", ".pbm",
                ".pdf", ".pgm", ".png", ".pnm", ".ppm", ".ppt", ".pptx", ".ra", ".ram", ".rar", ".ras", ".rgb", ".rmi",
                ".rtf", ".snd", ".svg", ".swf", ".tar", ".tif", ".tiff", ".ttf", ".vsd", ".wav", ".weba", ".webm",
                ".webp", ".woff", ".woff2", ".xbm", ".xls", ".xlsx", ".xpm", ".xul", ".xwd", ".zip", ".zip", ".js");
        try {
            URL request_url = new URL(baseRequestResponse.request().url());
            String path = request_url.getPath();

            // 2. 提取最后一个点之后的内容作为后缀
            String extension = "";
            int lastDotIndex = path.lastIndexOf('.');
            if (lastDotIndex > 0 && lastDotIndex < path.length() - 1) {
                extension = "."+path.substring(lastDotIndex + 1).toLowerCase();
            }
            if (Pattern.matches(urlWhitelistText, baseRequestResponse.request().url())) {
                return auditResult();
            }
            for (int i = 0; i < list.size(); i++) {
                String type = list.get(i);
                if (extension.equals(type) && !request_url.getHost().contains(type)) {
                    return auditResult();
                }
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        for (ParsedHttpParameter parameter : parameters) {
            String parameter_value = parameter.value();
            if (parameter.type().toString() == "BODY" || parameter.type().toString() == "URL") {
                if (Pattern.matches(paramWhitelistText, parameter.name())) {
                    continue;
                }
                if (parameter_value.equals("")) {
                    parameter_value = "1";
                }
                if (isNumericZidai(parameter_value)) {
                    HttpParameter updatedParameter = HttpParameter.parameter(parameter.name(), parameter_value + "-a",
                            parameter.type());
                    HttpRequest checkRequest = baseRequestResponse.request().withUpdatedParameters(updatedParameter);
                    HttpRequestResponse checkRequestResponse = sendrequest(checkRequest);
                    String response_body1 = checkRequestResponse.response().bodyToString();
                    double similarity1 = similar.lengthRatio(response_body, response_body1);
                    if (similarity1 > 0.08) {
                        HttpParameter updatedParameter2 = HttpParameter.parameter(parameter.name(),
                                parameter_value + "-1",
                                parameter.type());
                        HttpRequest checkRequest2 = baseRequestResponse.request()
                                .withUpdatedParameters(updatedParameter2);
                        HttpRequestResponse checkRequestResponse2 = sendrequest(checkRequest2);
                        String response_body2 = checkRequestResponse2.response().bodyToString();
                        double similarity = similar.lengthRatio(response_body1, response_body2);
                        if (similarity > 0.08) {
                            List<HttpRequestResponse> requestResponseList = new ArrayList<>();
                            requestResponseList.add(
                                    HttpRequestResponse.httpRequestResponse(checkRequest,
                                            checkRequestResponse.response()));
                            requestResponseList.add(HttpRequestResponse.httpRequestResponse(checkRequest2,
                                    checkRequestResponse2.response()));
                            auditIssueList.add(
                                    auditIssue(
                                            "SQL!",
                                            parameter.name(),
                                            null,
                                            baseRequestResponse.request().url(),
                                            AuditIssueSeverity.HIGH,
                                            AuditIssueConfidence.CERTAIN,
                                            null,
                                            null,
                                            AuditIssueSeverity.HIGH,
                                            requestResponseList));

                        }
                    }

                }
                HttpParameter updatedParameter = HttpParameter.parameter(parameter.name(), parameter_value + "%27%22",
                        parameter.type());
                HttpRequest checkRequest = baseRequestResponse.request().withUpdatedParameters(updatedParameter);
                HttpRequestResponse checkRequestResponse = sendrequest(checkRequest);
                String response_body1 = checkRequestResponse.response().bodyToString();
                double similarity1 = similar.lengthRatio(response_body, response_body1);
                if (similarity1 > 0.08) {
                    HttpParameter updatedParameter2 = HttpParameter.parameter(parameter.name(),
                            parameter_value + "%27%27%22%22",
                            parameter.type());
                    HttpRequest checkRequest2 = baseRequestResponse.request().withUpdatedParameters(updatedParameter2);
                    HttpRequestResponse checkRequestResponse2 = sendrequest(checkRequest2);
                    String response_body2 = checkRequestResponse2.response().bodyToString();
                    double similarity = similar.lengthRatio(response_body1, response_body2);
                    if (similarity > 0.08) {
                        List<HttpRequestResponse> requestResponseList = new ArrayList<>();
                        requestResponseList.add(
                                HttpRequestResponse.httpRequestResponse(checkRequest, checkRequestResponse.response()));
                        requestResponseList.add(HttpRequestResponse.httpRequestResponse(checkRequest2,
                                checkRequestResponse2.response()));
                        auditIssueList.add(
                                auditIssue(
                                        "SQL!",
                                        parameter.name(),
                                        null,
                                        baseRequestResponse.request().url(),
                                        AuditIssueSeverity.HIGH,
                                        AuditIssueConfidence.CERTAIN,
                                        null,
                                        null,
                                        AuditIssueSeverity.HIGH,
                                        requestResponseList));

                    }

                }
                updatedParameter = HttpParameter.parameter(parameter.name(), parameter_value + ",aaaa",
                        parameter.type());
                checkRequest = baseRequestResponse.request().withUpdatedParameters(updatedParameter);
                checkRequestResponse = sendrequest(checkRequest);
                response_body1 = checkRequestResponse.response().bodyToString();
                similarity1 = similar.lengthRatio(response_body, response_body1);
                if (similarity1 > 0.08) {
                    HttpParameter updatedParameter2 = HttpParameter.parameter(parameter.name(),
                            parameter_value + ",true",
                            parameter.type());
                    HttpRequest checkRequest2 = baseRequestResponse.request().withUpdatedParameters(updatedParameter2);
                    HttpRequestResponse checkRequestResponse2 = sendrequest(checkRequest2);
                    String response_body2 = checkRequestResponse2.response().bodyToString();
                    double similarity = similar.lengthRatio(response_body1, response_body2);
                    if (similarity > 0.08) {
                        List<HttpRequestResponse> requestResponseList = new ArrayList<>();
                        requestResponseList.add(
                                HttpRequestResponse.httpRequestResponse(checkRequest, checkRequestResponse.response()));
                        requestResponseList.add(HttpRequestResponse.httpRequestResponse(checkRequest2,
                                checkRequestResponse2.response()));
                        auditIssueList.add(
                                auditIssue(
                                        "SQL!",
                                        parameter.name(),
                                        null,
                                        baseRequestResponse.request().url(),
                                        AuditIssueSeverity.HIGH,
                                        AuditIssueConfidence.CERTAIN,
                                        null,
                                        null,
                                        AuditIssueSeverity.HIGH,
                                        requestResponseList));

                    }
                }
            }

        }
        // json
        if (request_body.contains("\":\"")
                || request_body.contains("\":[\"")) {
            // json list
            Pattern p_list = Pattern.compile("(\"|\\\\\")(\\S+?)(\"|\\\\\"):\\[(.*?)\\]");
            Matcher m_list = p_list.matcher(request_body);
            String json_list = null;
            String json_key = null;
            String e_str = null;
            String[] list_values = new String[0];
            while (m_list.find()) {
                json_key = m_list.group(2);
                json_list = m_list.group();
                list_values = m_list.group(4).split(",");
                e_str = m_list.group(3);
                boolean fg = false;// 列表只需要执行一次
                for (String list_value : list_values) {
                    if (fg) {
                        continue;
                    }
                    fg = true;
                    String real_list_value = list_value;
                    if (!list_value.contains("\"")) {
                        list_value = e_str + list_value + e_str;
                    }
                    if (real_list_value == "") {
                        continue;
                    }
                    // value为空时的处理
                    if (list_value.equals(e_str + e_str)) {
                        list_value = e_str + "1" + e_str;
                    }
                    String json_value = list_value.replace(e_str, "");
                    if (isNumericZidai(json_value)) {
                        String new_json_list = json_list.replace(real_list_value,
                                list_value.replace(json_value, json_value + "-a"));
                        String new_request_body = request_body.replace(json_list, new_json_list);
                        if(is_urlencode){
                            new_request_body = URLEncoder.encode(new_request_body).replace("%3D","=").replace("%26","&");
                        }
                        HttpRequest new_request = baseRequestResponse.request().withBody(new_request_body);
                        HttpRequestResponse new_response = sendrequest(new_request);
                        String response_body1 = new_response.response().bodyToString();
                        double similarity1 = similar.lengthRatio(response_body, response_body1);
                        if (similarity1 > 0.08) {
                            String new_json_list2 = json_list.replace(real_list_value,
                                    list_value.replace(json_value, json_value + "-1"));
                            String new_request_body2 = request_body.replace(json_list, new_json_list2);
                            HttpRequest new_request2 = baseRequestResponse.request().withBody(new_request_body2);
                            HttpRequestResponse new_response2 = sendrequest(new_request2);
                            String response_body2 = new_response2.response().bodyToString();
                            double similarity = similar.lengthRatio(response_body1, response_body2);
                            if (similarity > 0.08) {
                                List<HttpRequestResponse> requestResponseList = new ArrayList<>();
                                requestResponseList.add(
                                        HttpRequestResponse.httpRequestResponse(new_request, new_response.response()));
                                requestResponseList.add(HttpRequestResponse.httpRequestResponse(new_request2,
                                        new_response2.response()));
                                auditIssueList.add(
                                        auditIssue(
                                                "SQL!",
                                                json_key,
                                                null,
                                                baseRequestResponse.request().url(),
                                                AuditIssueSeverity.HIGH,
                                                AuditIssueConfidence.CERTAIN,
                                                null,
                                                null,
                                                AuditIssueSeverity.HIGH,
                                                requestResponseList));
                            }
                        }

                    }
                    String new_json_list = json_list.replace(real_list_value,
                            list_value.replace(json_value,
                                    json_value + "'" + e_str.replace("\"", "") + e_str.replace("\"", "") + "\\\""));
                    String new_request_body = request_body.replace(json_list, new_json_list);
                    if(is_urlencode){
                            new_request_body = URLEncoder.encode(new_request_body).replace("%3D","=").replace("%26","&");
                        }
                    HttpRequest new_request = baseRequestResponse.request().withBody(new_request_body);
                    HttpRequestResponse new_response = sendrequest(new_request);
                    String response_body1 = new_response.response().bodyToString();
                    double similarity1 = similar.lengthRatio(response_body, response_body1);
                    if (similarity1 > 0.08) {
                        String new_json_list2 = json_list.replace(real_list_value,
                                list_value.replace(json_value,
                                        json_value + "''" + e_str.replace("\"", "") + e_str.replace("\"", "") + "\\\""
                                                + e_str.replace("\"", "") + e_str.replace("\"", "") + "\\\""));
                        String new_request_body2 = request_body.replace(json_list, new_json_list2);
                        if(is_urlencode){
                            new_request_body2 = URLEncoder.encode(new_request_body2).replace("%3D","=").replace("%26","&");
                        }
                        HttpRequest new_request2 = baseRequestResponse.request().withBody(new_request_body2);
                        HttpRequestResponse new_response2 = sendrequest(new_request2);
                        String response_body2 = new_response2.response().bodyToString();
                        double similarity = similar.lengthRatio(response_body1, response_body2);
                        if (similarity > 0.08) {
                            List<HttpRequestResponse> requestResponseList = new ArrayList<>();
                            requestResponseList
                                    .add(HttpRequestResponse.httpRequestResponse(new_request, new_response.response()));
                            requestResponseList.add(
                                    HttpRequestResponse.httpRequestResponse(new_request2, new_response2.response()));
                            auditIssueList.add(
                                    auditIssue(
                                            "SQL!",
                                            json_key,
                                            null,
                                            baseRequestResponse.request().url(),
                                            AuditIssueSeverity.HIGH,
                                            AuditIssueConfidence.CERTAIN,
                                            null,
                                            null,
                                            AuditIssueSeverity.HIGH,
                                            requestResponseList));
                        }
                    }

                    String order_by_json_list = json_list.replace(real_list_value,
                            list_value.replace(json_value, json_value + ",aaaa"));
                    String order_by_request_body = request_body.replace(json_list, order_by_json_list);
                    if(is_urlencode){
                        order_by_request_body = URLEncoder.encode(order_by_request_body).replace("%3D","=").replace("%26","&");
                    }
                    HttpRequest order_by_request = baseRequestResponse.request().withBody(order_by_request_body);
                    HttpRequestResponse order_by_response = sendrequest(order_by_request);
                    String order_by_response_body1 = order_by_response.response().bodyToString();
                    double order_by_similarity1 = similar.lengthRatio(response_body, order_by_response_body1);
                    if (order_by_similarity1 > 0.08) {
                        String order_by_json_list2 = json_list.replace(real_list_value,
                                list_value.replace(json_value, json_value + ",true"));
                        String order_by_request_body2 = request_body.replace(json_list, order_by_json_list2);
                        if(is_urlencode){
                            order_by_request_body2 = URLEncoder.encode(order_by_request_body2).replace("%3D","=").replace("%26","&");
                        }
                        HttpRequest order_by_request2 = baseRequestResponse.request().withBody(order_by_request_body2);
                        HttpRequestResponse order_by_response2 = sendrequest(order_by_request2);
                        String response_body2 = order_by_response2.response().bodyToString();
                        double similarity = similar.lengthRatio(response_body1, response_body2);
                        if (similarity > 0.08) {
                            List<HttpRequestResponse> requestResponseList = new ArrayList<>();
                            requestResponseList
                                    .add(HttpRequestResponse.httpRequestResponse(order_by_request,
                                            order_by_response.response()));
                            requestResponseList.add(
                                    HttpRequestResponse.httpRequestResponse(order_by_request2,
                                            order_by_response2.response()));
                            auditIssueList.add(
                                    auditIssue(
                                            "SQL!",
                                            json_key,
                                            null,
                                            baseRequestResponse.request().url(),
                                            AuditIssueSeverity.HIGH,
                                            AuditIssueConfidence.CERTAIN,
                                            null,
                                            null,
                                            AuditIssueSeverity.HIGH,
                                            requestResponseList));
                        }
                    }
                }
            }
            // json
            String pattern = "(\"|\\\\\")(\\S+?)(\"|\\\\\"):(\"|\\\\\")(?!\\{)(.*?)(\"|\\\\\")";
            Pattern r = Pattern.compile(pattern);
            Matcher m = r.matcher(request_body);
            while (m.find()) {
                String json_e_str = m.group(3).replace("\"", "");
                String json_real_key = m.group(2);
                String json_key1 = m.group(2) + m.group(3);
                String json_real_value = m.group(5);
                String json_value1 = m.group(4) + m.group(5);
                // print(json_value1);
                if (Pattern.matches(paramWhitelistText, json_real_key)) {
                    continue;
                }
                if ((json_value1.startsWith("\"") || json_value1.startsWith("\\\"") && !json_value1.startsWith("["))) {
                    String old_para = json_key1 + ":" + json_value1;
                    String new_para1 = "";
                    String new_para2 = "";
                    if (json_value1.endsWith("\"")) {
                        json_value1 = json_value1 + "1";
                        json_real_value = "1";
                    }
                    if (isNumericZidai(json_real_value)) {
                        new_para1 = json_key1 + ":" + json_value1 + "-a";
                        new_para2 = json_key1 + ":" + json_value1 + "-0";
                        String new_request_body1 = request_body.replace(old_para, new_para1);
                        if(is_urlencode){
                            new_request_body1 = URLEncoder.encode(new_request_body1).replace("%3D","=").replace("%26","&");
                        }
                        HttpRequest request1 = baseRequestResponse.request().withBody(new_request_body1);
                        HttpRequestResponse response1 = sendrequest(request1);
                        String response1_body = response1.response().bodyToString();
                        double json_similarity1 = similar.lengthRatio(response_body, response1_body);
                        if (json_similarity1 > 0.08) {
                            String new_request_body2 = request_body.replace(old_para, new_para2);
                            if(is_urlencode){
                                new_request_body2 = URLEncoder.encode(new_request_body2).replace("%3D","=").replace("%26","&");
                            }
                            HttpRequest request2 = baseRequestResponse.request().withBody(new_request_body2);
                            HttpRequestResponse response2 = sendrequest(request2);
                            String response2_body = response2.response().bodyToString();
                            double json_similarity = similar.lengthRatio(response1_body, response2_body);
                            if (json_similarity > 0.08) {
                                List<HttpRequestResponse> requestResponseList = new ArrayList<>();
                                requestResponseList
                                        .add(HttpRequestResponse.httpRequestResponse(request1, response1.response()));
                                requestResponseList.add(
                                        HttpRequestResponse.httpRequestResponse(request2, response2.response()));
                                auditIssueList.add(
                                        auditIssue(
                                                "SQL!",
                                                json_real_key,
                                                null,
                                                baseRequestResponse.request().url(),
                                                AuditIssueSeverity.HIGH,
                                                AuditIssueConfidence.CERTAIN,
                                                null,
                                                null,
                                                AuditIssueSeverity.HIGH,
                                                requestResponseList));

                            }

                        }
                    }
                    new_para1 = json_key1 + ":" + json_value1 + "'" + json_e_str + json_e_str + "\\\"";
                    new_para2 = json_key1 + ":" + json_value1 + "''" + json_e_str + json_e_str + "\\\"" + json_e_str
                            + json_e_str + "\\\"";
                    String new_request_body1 = request_body.replace(old_para, new_para1);
                    if(is_urlencode){
                        new_request_body1 = URLEncoder.encode(new_request_body1).replace("%3D","=").replace("%26","&");
                    }
                    HttpRequest request1 = baseRequestResponse.request().withBody(new_request_body1);
                    HttpRequestResponse response1 = sendrequest(request1);
                    String response1_body = response1.response().bodyToString();
                    double json_similarity1 = similar.lengthRatio(response_body, response1_body);
                    if (json_similarity1 > 0.08) {
                        String new_request_body2 = request_body.replace(old_para, new_para2);
                        if(is_urlencode){
                            new_request_body2 = URLEncoder.encode(new_request_body2).replace("%3D","=").replace("%26","&");
                        }
                        HttpRequest request2 = baseRequestResponse.request().withBody(new_request_body2);
                        HttpRequestResponse response2 = sendrequest(request2);
                        String response2_body = response2.response().bodyToString();
                        double json_similarity = similar.lengthRatio(response1_body, response2_body);
                        if (json_similarity > 0.08) {
                            List<HttpRequestResponse> requestResponseList = new ArrayList<>();
                            requestResponseList
                                    .add(HttpRequestResponse.httpRequestResponse(request1, response1.response()));
                            requestResponseList.add(
                                    HttpRequestResponse.httpRequestResponse(request2, response2.response()));
                            auditIssueList.add(
                                    auditIssue(
                                            "SQL!",
                                            json_real_key,
                                            null,
                                            baseRequestResponse.request().url(),
                                            AuditIssueSeverity.HIGH,
                                            AuditIssueConfidence.CERTAIN,
                                            null,
                                            null,
                                            AuditIssueSeverity.HIGH,
                                            requestResponseList));

                        }

                    }
                    String order_by_para1 = json_key1 + ":" + json_value1 + ",aaaa";
                    String order_by_para2 = json_key1 + ":" + json_value1 + ",true";
                    String order_by_request_body1 = request_body.replace(old_para, order_by_para1);
                    if(is_urlencode){
                        order_by_request_body1 = URLEncoder.encode(order_by_request_body1).replace("%3D","=").replace("%26","&");
                    }
                    HttpRequest order_by_request1 = baseRequestResponse.request().withBody(order_by_request_body1);
                    HttpRequestResponse order_by_response1 = sendrequest(order_by_request1);
                    String order_by_response1_body = order_by_response1.response().bodyToString();
                    double order_by_json_similarity1 = similar.lengthRatio(response_body, order_by_response1_body);
                    if (order_by_json_similarity1 > 0.08) {
                        String order_by_request_body2 = request_body.replace(old_para, order_by_para2);
                        if(is_urlencode){
                            order_by_request_body2 = URLEncoder.encode(order_by_request_body2).replace("%3D","=").replace("%26","&");
                        }
                        HttpRequest order_by_request2 = baseRequestResponse.request().withBody(order_by_request_body2);
                        HttpRequestResponse order_by_response2 = sendrequest(order_by_request2);
                        String order_by_response2_body = order_by_response2.response().bodyToString();
                        double json_similarity = similar.lengthRatio(order_by_response1_body, order_by_response2_body);
                        if (json_similarity > 0.08) {
                            List<HttpRequestResponse> requestResponseList = new ArrayList<>();
                            requestResponseList
                                    .add(HttpRequestResponse.httpRequestResponse(order_by_request1,
                                            order_by_response1.response()));
                            requestResponseList.add(
                                    HttpRequestResponse.httpRequestResponse(order_by_request2,
                                            order_by_response2.response()));
                            auditIssueList.add(
                                    auditIssue(
                                            "SQL!",
                                            json_real_key,
                                            null,
                                            baseRequestResponse.request().url(),
                                            AuditIssueSeverity.HIGH,
                                            AuditIssueConfidence.CERTAIN,
                                            null,
                                            null,
                                            AuditIssueSeverity.HIGH,
                                            requestResponseList));

                        }

                    }
            

                }
            }
            //处理数字无双引号包裹
            String pattern2 = "(\"|\\\\\")(\\S+?)(\"|\\\\\")(:\\[?)(\\d+)";
            Pattern r2 = Pattern.compile(pattern2);
            // print(request_body);
            Matcher m2 = r2.matcher(request_body);
            while (m2.find()) {
                String json_e_str = m2.group(3).replace("\"", "");
                String json_real_key = m2.group(2);
                String json_group_3 = m2.group(3);
                String json_key1 = m2.group(2) + m2.group(3);
                String json_real_value = m2.group(5);
                String json_value1 = m2.group(5);
                // print(json_value1);
                if (Pattern.matches(paramWhitelistText, json_real_key)) {
                    continue;
                }
                String old_para = json_key1 + ":" + json_real_value;
                String new_para1 = "";
                String new_para2 = "";
                if (isNumericZidai(json_real_value)) {
                    new_para1 = json_key1 + ":"+ json_group_3 +json_real_value + "-a"+json_group_3;
                    new_para2 = json_key1 + ":"+json_group_3 + json_value1 + "-0"+json_group_3;
                    String new_request_body1 = request_body.replace(old_para, new_para1);
                    if(is_urlencode){
                        new_request_body1 = URLEncoder.encode(new_request_body1).replace("%3D","=").replace("%26","&");
                    }
                    HttpRequest request1 = baseRequestResponse.request().withBody(new_request_body1);
                    HttpRequestResponse response1 = sendrequest(request1);
                    String response1_body = response1.response().bodyToString();
                    double json_similarity1 = similar.lengthRatio(response_body, response1_body);
                    if (json_similarity1 > 0.08) {
                        String new_request_body2 = request_body.replace(old_para, new_para2);
                        if(is_urlencode){
                            new_request_body2 = URLEncoder.encode(new_request_body2).replace("%3D","=").replace("%26","&");
                        }
                        HttpRequest request2 = baseRequestResponse.request().withBody(new_request_body2);
                        HttpRequestResponse response2 = sendrequest(request2);
                        String response2_body = response2.response().bodyToString();
                        double json_similarity = similar.lengthRatio(response1_body, response2_body);
                        if (json_similarity > 0.08) {
                            List<HttpRequestResponse> requestResponseList = new ArrayList<>();
                            requestResponseList
                                    .add(HttpRequestResponse.httpRequestResponse(request1, response1.response()));
                            requestResponseList.add(
                                    HttpRequestResponse.httpRequestResponse(request2, response2.response()));
                            auditIssueList.add(
                                    auditIssue(
                                            "SQL!",
                                            json_real_key,
                                            null,
                                            baseRequestResponse.request().url(),
                                            AuditIssueSeverity.HIGH,
                                            AuditIssueConfidence.CERTAIN,
                                            null,
                                            null,
                                            AuditIssueSeverity.HIGH,
                                            requestResponseList));

                        }

                    }
                }
                new_para1 = json_key1 + ":"+json_group_3 + json_value1 + "'" + json_e_str + json_e_str + "\\\""+json_group_3;
                new_para2 = json_key1 + ":"+json_group_3 + json_value1 + "''" + json_e_str + json_e_str + "\\\"" + json_e_str
                        + json_e_str + "\\\""+json_group_3;
                String new_request_body1 = request_body.replace(old_para, new_para1);
                if(is_urlencode){
                    new_request_body1 = URLEncoder.encode(new_request_body1).replace("%3D","=").replace("%26","&");
                }
                HttpRequest request1 = baseRequestResponse.request().withBody(new_request_body1);
                HttpRequestResponse response1 = sendrequest(request1);
                String response1_body = response1.response().bodyToString();
                double json_similarity1 = similar.lengthRatio(response_body, response1_body);
                if (json_similarity1 > 0.08) {
                    String new_request_body2 = request_body.replace(old_para, new_para2);
                    if(is_urlencode){
                        new_request_body2 = URLEncoder.encode(new_request_body2).replace("%3D","=").replace("%26","&");
                    }
                    HttpRequest request2 = baseRequestResponse.request().withBody(new_request_body2);
                    HttpRequestResponse response2 = sendrequest(request2);
                    String response2_body = response2.response().bodyToString();
                    double json_similarity = similar.lengthRatio(response1_body, response2_body);
                    if (json_similarity > 0.08) {
                        List<HttpRequestResponse> requestResponseList = new ArrayList<>();
                        requestResponseList
                                .add(HttpRequestResponse.httpRequestResponse(request1, response1.response()));
                        requestResponseList.add(
                                HttpRequestResponse.httpRequestResponse(request2, response2.response()));
                        auditIssueList.add(
                                auditIssue(
                                        "SQL!",
                                        json_real_key,
                                        null,
                                        baseRequestResponse.request().url(),
                                        AuditIssueSeverity.HIGH,
                                        AuditIssueConfidence.CERTAIN,
                                        null,
                                        null,
                                        AuditIssueSeverity.HIGH,
                                        requestResponseList));

                    }

                }
                String order_by_para1 = json_key1 + ":" +json_group_3+ json_value1 + ",aaaa"+json_group_3;
                String order_by_para2 = json_key1 + ":" +json_group_3+ json_value1 + ",true"+json_group_3;
                String order_by_request_body1 = request_body.replace(old_para, order_by_para1);
                if(is_urlencode){
                    order_by_request_body1 = URLEncoder.encode(order_by_request_body1).replace("%3D","=").replace("%26","&");
                }
                HttpRequest order_by_request1 = baseRequestResponse.request().withBody(order_by_request_body1);
                HttpRequestResponse order_by_response1 = sendrequest(order_by_request1);
                String order_by_response1_body = order_by_response1.response().bodyToString();
                double order_by_json_similarity1 = similar.lengthRatio(response_body, order_by_response1_body);
                if (order_by_json_similarity1 > 0.08) {
                    String order_by_request_body2 = request_body.replace(old_para, order_by_para2);
                    if(is_urlencode){
                        order_by_request_body2 = URLEncoder.encode(order_by_request_body2).replace("%3D","=").replace("%26","&");
                    }
                    HttpRequest order_by_request2 = baseRequestResponse.request().withBody(order_by_request_body2);
                    HttpRequestResponse order_by_response2 = sendrequest(order_by_request2);
                    String order_by_response2_body = order_by_response2.response().bodyToString();
                    double json_similarity = similar.lengthRatio(order_by_response1_body, order_by_response2_body);
                    if (json_similarity > 0.08) {
                        List<HttpRequestResponse> requestResponseList = new ArrayList<>();
                        requestResponseList
                                .add(HttpRequestResponse.httpRequestResponse(order_by_request1,
                                        order_by_response1.response()));
                        requestResponseList.add(
                                HttpRequestResponse.httpRequestResponse(order_by_request2,
                                        order_by_response2.response()));
                        auditIssueList.add(
                                auditIssue(
                                        "SQL!",
                                        json_real_key,
                                        null,
                                        baseRequestResponse.request().url(),
                                        AuditIssueSeverity.HIGH,
                                        AuditIssueConfidence.CERTAIN,
                                        null,
                                        null,
                                        AuditIssueSeverity.HIGH,
                                        requestResponseList));

                    }

                }
        

                
            }

        }

        return auditResult(auditIssueList);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return existingIssue.name().equals(newIssue.name()) ? KEEP_EXISTING : KEEP_BOTH;
    }
}