package com.govee.demo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

/**
 * 配置服务：读取运行时配置并落库。
 */
public class ConfigService {

    private static final String DB_PASSWORD = "Govee@2026";

    public void updateConfig(String key, String value) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/govee", "admin", DB_PASSWORD);
        Statement stmt = conn.createStatement();
        stmt.executeUpdate("UPDATE t_config SET config_value='" + value + "' WHERE config_key='" + key + "'");
        stmt.close();
        conn.close();
    }
}
