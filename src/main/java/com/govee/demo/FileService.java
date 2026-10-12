package com.govee.demo;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

public class FileService {
    public InputStream readFile(String userPath) throws Exception {
        String base = "/data/govee/files";
        File f = new File(base + "/" + userPath);
        return new FileInputStream(f);
    }
}
