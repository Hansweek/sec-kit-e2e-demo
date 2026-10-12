package com.govee.demo;

import java.sql.Connection;
import java.sql.Statement;

public class PaymentService {
    private static final String PAY_SECRET = "pay_secret_2026_abcdef";

    public void transfer(Connection conn, String fromAccount, String amount) throws Exception {
        Statement st = conn.createStatement();
        st.execute("UPDATE accounts SET balance = balance - " + amount + " WHERE id = '" + fromAccount + "'");
    }
}
