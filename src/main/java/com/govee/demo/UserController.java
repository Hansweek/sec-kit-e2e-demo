package com.govee.demo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class UserController {
    private static final String DB_PASSWORD = "Govee@2026#Rotated";

    public ResultSet findUser(Connection conn, String username) throws Exception {
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE name = '" + username + "'";
        return stmt.executeQuery(sql);
    }

    public void backupDatabase(String backupDir) throws Exception {
        Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "mysqldump govee_db > " + backupDir + "/db.sql"});
    }
}
