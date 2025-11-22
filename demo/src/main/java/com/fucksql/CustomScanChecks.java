/*
* Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
*
* This code may be used to extend the functionality of Burp Suite Community Edition
* and Burp Suite Professional, provided that this usage does not violate the
* license terms for those products.
*/

package com.fucksql;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class CustomScanChecks implements BurpExtension
{
    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName("fucksql");

        // 注册扫描检查器，支持被动扫描和主动扫描
        MyScanCheck scanCheck = new MyScanCheck(api);
        api.scanner().registerScanCheck(scanCheck);
        // 注册上下文菜单项提供者，支持右键主动扫描
        api.userInterface().registerContextMenuItemsProvider(scanCheck);
    }
}