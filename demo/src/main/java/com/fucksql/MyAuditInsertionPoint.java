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
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.core.ToolType;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenuItem;
import java.awt.Component;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

class MyScanCheck implements ScanCheck, ContextMenuItemsProvider,PassiveScanCheck {
    StringSimilarity similar = new StringSimilarity();
    private final MontoyaApi api;
    private int packetDelay = 0;
    private String scanHostsText = "";
    private String excludeParamsText = "";
    boolean projectFilterEnabled = true;
    boolean passiveScanEnabled = false; // 被动扫描开关状态，默认关闭
    boolean hostFilterEnabled = false; // host列表过滤开关状态，默认关闭
    boolean paramExclusionEnabled = true; // 参数排除开关状态，默认开启
    private volatile boolean isAnyActiveScanRunning = false; // 标记是否有任何主动扫描正在运行
    private ThreadLocal<Boolean> isActiveScanThread = ThreadLocal.withInitial(() -> false); // 标记当前线程是否是主动扫描线程
    // 保存CustomPanel实例引用
    private CustomPanel customPanel;

    MyScanCheck(MontoyaApi api) {
        this.api = api;
        this.customPanel = new CustomPanel();
        api.userInterface().registerSuiteTab("SQL config", customPanel);
        customPanel.getConfirmButton().addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                packetDelay = customPanel.getPacketDelay();
                scanHostsText = customPanel.getScanHostsText();
                excludeParamsText = customPanel.getExcludeParamsText();
                projectFilterEnabled = customPanel.isProjectFilterEnabled();
                passiveScanEnabled = customPanel.isPassiveScanEnabled(); // 获取被动扫描开关状态
                hostFilterEnabled = customPanel.isHostFilterEnabled(); // 获取host列表过滤开关状态
                paramExclusionEnabled = customPanel.isParamExclusionEnabled(); // 获取参数排除开关状态
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
        if (packetDelay > 0) {
            try {
                Thread.sleep(packetDelay * 1000L);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        HttpRequestResponse requestresponse = api.http().sendRequest(request);
        return requestresponse;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        // 检查被动扫描是否启用，如果未启用则直接返回
        if (!passiveScanEnabled) {
            return auditResult();
        }

        // 如果有主动扫描正在运行，且当前线程不是主动扫描线程，则跳过被动扫描
        // 这样可以避免主动扫描期间产生的流量被重复扫描，但主动扫描本身的调用仍然会执行
        if (isAnyActiveScanRunning && !isActiveScanThread.get()) {
            return auditResult();
        }

        List<AuditIssue> auditIssueList = new ArrayList<>();
        // 每次执行扫描时，直接从UI获取最新的payload列表
        List<String[]> payloadList = customPanel.getPayloadList();

        // 跳过OPTIONS方法
        if (baseRequestResponse.request().method().equals("OPTIONS")) {
            return auditResult();
        }
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

        // 检查是否启用项目范围过滤
        if (projectFilterEnabled) {
            if (!api.scope().isInScope(baseRequestResponse.request().url())) {
                return auditResult(); // URL不在项目范围内，不进行扫描
            }
        }

        // 检查URL是否在扫描host列表中（仅当hostFilterEnabled为true时应用）
        if (hostFilterEnabled && !scanHostsText.isEmpty()) {
            boolean match = false;
            try {
                URL request_url = new URL(baseRequestResponse.request().url());
                String host = request_url.getHost();
                for (String pattern : scanHostsText.split("\\n")) {
                    if (!pattern.trim().isEmpty() && host.matches(pattern.trim())) {
                        match = true;
                        break;
                    }
                }
            } catch (MalformedURLException e) {
                // URL解析错误，跳过此URL
                return auditResult();
            }
            if (!match) {
                return auditResult(); // URL不在扫描host列表中，不进行扫描
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
                extension = "." + path.substring(lastDotIndex + 1).toLowerCase();
            }
            // 已经在前面处理了扫描host列表的逻辑，这里不再需要URL白名单检查
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
            // 修正字符串比较方法，使用equals而不是==
            if (parameter.type().toString().equals("BODY") || parameter.type().toString().equals("URL")) {
                // 检查参数是否在排除列表中（仅当paramExclusionEnabled为true时应用）
                if (paramExclusionEnabled && !excludeParamsText.isEmpty()) {
                    boolean exclude = false;
                    for (String excludePattern : excludeParamsText.split("\\n")) {
                        if (!excludePattern.trim().isEmpty() && parameter.name().matches(excludePattern.trim())) {
                            exclude = true;
                            break;
                        }
                    }
                    if (exclude) {
                        continue;
                    }
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
                                parameter_value + "-0",
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
                // 只在Payload1和Payload2的检测位置应用payload列表循环
                for (String[] payload : payloadList) {
                    String Payload1 = payload[0];
                    String Payload2 = payload[1];

                    HttpParameter updatedParameter = HttpParameter.parameter(parameter.name(),
                            parameter_value + URLEncoder.encode(Payload1),
                            parameter.type());
                    HttpRequest checkRequest = baseRequestResponse.request().withUpdatedParameters(updatedParameter);
                    HttpRequestResponse checkRequestResponse = sendrequest(checkRequest);
                    String response_body1 = checkRequestResponse.response().bodyToString();
                    double similarity1 = similar.lengthRatio(response_body, response_body1);
                    if (similarity1 > 0.08) {
                        HttpParameter updatedParameter2 = HttpParameter.parameter(parameter.name(),
                                parameter_value + URLEncoder.encode(Payload2),
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
                HttpParameter updatedParameter = HttpParameter.parameter(parameter.name(), parameter_value + ",0",
                        parameter.type());
                HttpRequest checkRequest = baseRequestResponse.request().withUpdatedParameters(updatedParameter);
                HttpRequestResponse checkRequestResponse = sendrequest(checkRequest);
                String response_body1 = checkRequestResponse.response().bodyToString();
                // order by
                double similarity1 = similar.lengthRatio(response_body, response_body1);
                if (similarity1 > 0.08) {
                    HttpParameter updatedParameter2 = HttpParameter.parameter(parameter.name(),
                            parameter_value + ",1",
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
        if (request_body.contains("\":")
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
                    // print(list_value);
                    if (list_value.equals(e_str + e_str)) {
                        list_value = e_str + "1" + e_str;
                    }
                    String json_value = list_value.replace(e_str, "");
                    if (isNumericZidai(json_value)) {
                        String new_json_list = json_list.replace(real_list_value,
                                list_value.replace(json_value, json_value + "-a"));
                        String new_request_body = request_body.replace(json_list, new_json_list);
                        if (is_urlencode) {
                            new_request_body = URLEncoder.encode(new_request_body).replace("%3D", "=").replace("%26",
                                    "&");
                        }
                        HttpRequest new_request = baseRequestResponse.request().withBody(new_request_body);
                        HttpRequestResponse new_response = sendrequest(new_request);
                        String response_body1 = new_response.response().bodyToString();
                        double similarity1 = similar.lengthRatio(response_body, response_body1);
                        if (similarity1 > 0.08) {
                            String new_json_list2 = json_list.replace(real_list_value,
                                    list_value.replace(json_value, json_value + "-0"));
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
                    // 只在Payload1和Payload2的检测位置应用payload列表循环
                    String response_body1 = "";
                    for (String[] payload : payloadList) {
                        String Payload1 = payload[0];
                        String Payload2 = payload[1];

                        String new_json_list = json_list.replace(real_list_value,
                                list_value.replace(json_value,
                                        json_value + Payload1));
                        String new_request_body = request_body.replace(json_list, new_json_list);
                        if (is_urlencode) {
                            new_request_body = URLEncoder.encode(new_request_body).replace("%3D", "=").replace("%26",
                                    "&");
                        }
                        HttpRequest new_request = baseRequestResponse.request().withBody(new_request_body);
                        HttpRequestResponse new_response = sendrequest(new_request);
                        response_body1 = new_response.response().bodyToString();
                        double similarity1 = similar.lengthRatio(response_body, response_body1);
                        if (similarity1 > 0.08) {
                            String new_json_list2 = json_list.replace(real_list_value,
                                    list_value.replace(json_value,
                                            json_value + Payload2));
                            String new_request_body2 = request_body.replace(json_list, new_json_list2);
                            if (is_urlencode) {
                                new_request_body2 = URLEncoder.encode(new_request_body2).replace("%3D", "=")
                                        .replace("%26", "&");
                            }
                            HttpRequest new_request2 = baseRequestResponse.request().withBody(new_request_body2);
                            HttpRequestResponse new_response2 = sendrequest(new_request2);
                            String response_body2 = new_response2.response().bodyToString();
                            double similarity = similar.lengthRatio(response_body1, response_body2);
                            if (similarity > 0.08) {
                                List<HttpRequestResponse> requestResponseList = new ArrayList<>();
                                requestResponseList
                                        .add(HttpRequestResponse.httpRequestResponse(new_request,
                                                new_response.response()));
                                requestResponseList.add(
                                        HttpRequestResponse.httpRequestResponse(new_request2,
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

                    String order_by_json_list = json_list.replace(real_list_value,
                            list_value.replace(json_value, json_value + ",0"));
                    String order_by_request_body = request_body.replace(json_list, order_by_json_list);
                    if (is_urlencode) {
                        order_by_request_body = URLEncoder.encode(order_by_request_body).replace("%3D", "=")
                                .replace("%26", "&");
                    }
                    HttpRequest order_by_request = baseRequestResponse.request().withBody(order_by_request_body);
                    HttpRequestResponse order_by_response = sendrequest(order_by_request);
                    String order_by_response_body1 = order_by_response.response().bodyToString();
                    double order_by_similarity1 = similar.lengthRatio(response_body, order_by_response_body1);
                    if (order_by_similarity1 > 0.08) {
                        String order_by_json_list2 = json_list.replace(real_list_value,
                                list_value.replace(json_value, json_value + ",1"));
                        String order_by_request_body2 = request_body.replace(json_list, order_by_json_list2);
                        if (is_urlencode) {
                            order_by_request_body2 = URLEncoder.encode(order_by_request_body2).replace("%3D", "=")
                                    .replace("%26", "&");
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
                // 检查参数是否在排除列表中
                if (!excludeParamsText.isEmpty()) {
                    boolean exclude = false;
                    for (String excludePattern : excludeParamsText.split("\\n")) {
                        if (!excludePattern.trim().isEmpty() && json_real_key.matches(excludePattern.trim())) {
                            exclude = true;
                            break;
                        }
                    }
                    if (exclude) {
                        continue;
                    }
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
                        if (is_urlencode) {
                            new_request_body1 = URLEncoder.encode(new_request_body1).replace("%3D", "=").replace("%26",
                                    "&");
                        }
                        HttpRequest request1 = baseRequestResponse.request().withBody(new_request_body1);
                        HttpRequestResponse response1 = sendrequest(request1);
                        String response1_body = response1.response().bodyToString();
                        double json_similarity1 = similar.lengthRatio(response_body, response1_body);
                        if (json_similarity1 > 0.08) {
                            String new_request_body2 = request_body.replace(old_para, new_para2);
                            if (is_urlencode) {
                                new_request_body2 = URLEncoder.encode(new_request_body2).replace("%3D", "=")
                                        .replace("%26", "&");
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
                    // 只在Payload1和Payload2的检测位置应用payload列表循环
                    for (String[] payload : payloadList) {
                        String Payload1 = payload[0];
                        String Payload2 = payload[1];

                        new_para1 = json_key1 + ":" + json_value1 + Payload1;
                        new_para2 = json_key1 + ":" + json_value1 + Payload2;
                        String new_request_body1 = request_body.replace(old_para, new_para1);
                        if (is_urlencode) {
                            new_request_body1 = URLEncoder.encode(new_request_body1).replace("%3D", "=").replace("%26",
                                    "&");
                        }
                        HttpRequest request1 = baseRequestResponse.request().withBody(new_request_body1);
                        HttpRequestResponse response1 = sendrequest(request1);
                        String response1_body = response1.response().bodyToString();
                        double json_similarity1 = similar.lengthRatio(response_body, response1_body);
                        if (json_similarity1 > 0.08) {
                            String new_request_body2 = request_body.replace(old_para, new_para2);
                            if (is_urlencode) {
                                new_request_body2 = URLEncoder.encode(new_request_body2).replace("%3D", "=")
                                        .replace("%26", "&");
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
                    String order_by_para1 = json_key1 + ":" + json_value1 + ",0";
                    String order_by_para2 = json_key1 + ":" + json_value1 + ",1";
                    String order_by_request_body1 = request_body.replace(old_para, order_by_para1);
                    if (is_urlencode) {
                        order_by_request_body1 = URLEncoder.encode(order_by_request_body1).replace("%3D", "=")
                                .replace("%26", "&");
                    }
                    HttpRequest order_by_request1 = baseRequestResponse.request().withBody(order_by_request_body1);
                    HttpRequestResponse order_by_response1 = sendrequest(order_by_request1);
                    String order_by_response1_body = order_by_response1.response().bodyToString();
                    double order_by_json_similarity1 = similar.lengthRatio(response_body, order_by_response1_body);
                    if (order_by_json_similarity1 > 0.08) {
                        String order_by_request_body2 = request_body.replace(old_para, order_by_para2);
                        if (is_urlencode) {
                            order_by_request_body2 = URLEncoder.encode(order_by_request_body2).replace("%3D", "=")
                                    .replace("%26", "&");
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
            // 处理数字无双引号包裹或者null
            String pattern2 = "(\"|\\\\\")(\\S+?)(\"|\\\\\")(:\\[?)(\\d+|null)";
            Pattern r2 = Pattern.compile(pattern2);
            Matcher m2 = r2.matcher(request_body);
            while (m2.find()) {
                String json_e_str = m2.group(3).replace("\"", "");
                String json_real_key = m2.group(2);
                String json_group_3 = m2.group(3);
                String json_key1 = m2.group(2) + m2.group(3);
                String json_real_value = m2.group(5);
                String json_value1 = m2.group(5);
                // print(json_real_value);
                if (json_real_value.equals("null")) {
                    json_value1 = "1";
                }
                // 检查参数是否在排除列表中
                if (!excludeParamsText.isEmpty()) {
                    boolean exclude = false;
                    for (String excludePattern : excludeParamsText.split("\\n")) {
                        if (!excludePattern.trim().isEmpty() && json_real_key.matches(excludePattern.trim())) {
                            exclude = true;
                            break;
                        }
                    }
                    if (exclude) {
                        continue;
                    }
                }
                String old_para = json_key1 + ":" + json_real_value;
                String new_para1 = "";
                String new_para2 = "";
                if (isNumericZidai(json_value1)) {
                    new_para1 = json_key1 + ":" + json_group_3 + json_value1 + "-a" + json_group_3;
                    new_para2 = json_key1 + ":" + json_group_3 + json_value1 + "-0" + json_group_3;
                    // print(old_para);
                    // print(new_para1);
                    String new_request_body1 = request_body.replace(old_para, new_para1);
                    if (is_urlencode) {
                        new_request_body1 = URLEncoder.encode(new_request_body1).replace("%3D", "=").replace("%26",
                                "&");
                    }
                    HttpRequest request1 = baseRequestResponse.request().withBody(new_request_body1);
                    HttpRequestResponse response1 = sendrequest(request1);
                    String response1_body = response1.response().bodyToString();
                    double json_similarity1 = similar.lengthRatio(response_body, response1_body);
                    if (json_similarity1 > 0.08) {
                        String new_request_body2 = request_body.replace(old_para, new_para2);
                        if (is_urlencode) {
                            new_request_body2 = URLEncoder.encode(new_request_body2).replace("%3D", "=").replace("%26",
                                    "&");
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
                // 只在Payload1和Payload2的检测位置应用payload列表循环
                for (String[] payload : payloadList) {
                    String Payload1 = payload[0];
                    String Payload2 = payload[1];

                    new_para1 = json_key1 + ":" + json_group_3 + json_value1 + Payload1 + json_e_str + "\"";
                    new_para2 = json_key1 + ":" + json_group_3 + json_value1 + Payload2 + json_e_str + "\"";
                    String new_request_body1 = request_body.replace(old_para, new_para1);
                    if (is_urlencode) {
                        new_request_body1 = URLEncoder.encode(new_request_body1).replace("%3D", "=").replace("%26",
                                "&");
                    }
                    HttpRequest request1 = baseRequestResponse.request().withBody(new_request_body1);
                    HttpRequestResponse response1 = sendrequest(request1);
                    String response1_body = response1.response().bodyToString();
                    double json_similarity1 = similar.lengthRatio(response_body, response1_body);
                    if (json_similarity1 > 0.08) {
                        String new_request_body2 = request_body.replace(old_para, new_para2);
                        if (is_urlencode) {
                            new_request_body2 = URLEncoder.encode(new_request_body2).replace("%3D", "=").replace("%26",
                                    "&");
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
                String order_by_para1 = json_key1 + ":" + json_group_3 + json_value1 + ",0" + json_group_3;
                String order_by_para2 = json_key1 + ":" + json_group_3 + json_value1 + ",1" + json_group_3;
                String order_by_request_body1 = request_body.replace(old_para, order_by_para1);
                if (is_urlencode) {
                    order_by_request_body1 = URLEncoder.encode(order_by_request_body1).replace("%3D", "=")
                            .replace("%26", "&");
                }
                HttpRequest order_by_request1 = baseRequestResponse.request().withBody(order_by_request_body1);
                HttpRequestResponse order_by_response1 = sendrequest(order_by_request1);
                String order_by_response1_body = order_by_response1.response().bodyToString();
                double order_by_json_similarity1 = similar.lengthRatio(response_body, order_by_response1_body);
                if (order_by_json_similarity1 > 0.08) {
                    String order_by_request_body2 = request_body.replace(old_para, order_by_para2);
                    if (is_urlencode) {
                        order_by_request_body2 = URLEncoder.encode(order_by_request_body2).replace("%3D", "=")
                                .replace("%26", "&");
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

        try {
            return auditResult(auditIssueList);
        } catch (Exception e) {
            e.printStackTrace();
            return auditResult();
        }
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return existingIssue.name().equals(newIssue.name()) ? KEEP_EXISTING : KEEP_BOTH;
    }

    // 主动扫描方法已在文件其他位置定义
    private void do_active_scan(HttpRequestResponse requestResponse) {
        new Thread(() -> {
            boolean isPassiveScanEnabled = passiveScanEnabled;
            boolean isProjectFilterEnabled = projectFilterEnabled;
            projectFilterEnabled = false;
            passiveScanEnabled = true;
            isAnyActiveScanRunning = true; // 标记有主动扫描正在运行
            isActiveScanThread.set(true); // 标记当前线程是主动扫描线程
            try {
                List<AuditIssue> auditIssueList = passiveAudit(requestResponse).auditIssues();
                for (AuditIssue auditIssue : auditIssueList) {
                    api.siteMap().add(auditIssue);
                }
            } finally {
                isActiveScanThread.set(false); // 清除主动扫描线程标记
                isAnyActiveScanRunning = false; // 清除主动扫描运行标记
                passiveScanEnabled = isPassiveScanEnabled;
                projectFilterEnabled = isProjectFilterEnabled;
            }
        }).start();
        
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // 修改逻辑：对于所有HTTP相关模块（包括Repeater），即使selectedItems为空也尝试添加菜单项
        // 在Burp Suite中，Repeater模块的右键菜单会通过selectedRequestResponses()返回数据
        JMenuItem scanMenuItem = new JMenuItem("使用FuckSQL主动扫描");
        scanMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                List<HttpRequestResponse> itemsToScan = event.selectedRequestResponses();
                if (itemsToScan != null && !itemsToScan.isEmpty()) {
                    // 遍历所有选中的请求/响应
                    for (HttpRequestResponse requestResponse : itemsToScan) {
                        if (requestResponse != null && requestResponse.request() != null) {

                            do_active_scan(requestResponse);

                        }
                    }
                } else {
                    HttpRequestResponse requestResponse = event.messageEditorRequestResponse().isPresent()
                            ? event.messageEditorRequestResponse().get().requestResponse()
                            : event.selectedRequestResponses().get(0);

                    do_active_scan(requestResponse);
                }
            }
        });

        // 在所有HTTP相关模块中添加菜单项，而不仅限于有选中项的情况
        // 这是为了确保在Repeater等模块中能正确显示菜单
        menuItems.add(scanMenuItem);

        return menuItems;
    }

    @Override
    public String checkName() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'checkName'");
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse arg0) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'doCheck'");
    }
}