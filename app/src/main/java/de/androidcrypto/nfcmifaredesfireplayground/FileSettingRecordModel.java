package de.androidcrypto.nfcmifaredesfireplayground;

import android.util.Log;

import java.util.Arrays;

public class FileSettingRecordModel {

    private static final String TAG = "FileSettingRecordModel";
    // data in File Settings dataset
    private byte fileNumber;
    private byte fileType; // 04 for record based files see DESFire EV protocol
    private byte communicationSettings;
    private byte accessRightRwCar;
    private byte accessRightRW;
    private byte[] recordSizeByte; // 3 bytes
    private byte[] maxRecordsByte; // 3 bytes: beware - the last record is a spare record for writing so the real maximum is maxRecordByte - 1
    private byte[] recordsExistingByte; // 3 bytes
    private int recordSize;
    private int maxRecords;
    private int recordsExisting;
    public final byte fileTypeStandardFile = (byte) 0x00;
    public final byte fileTypeBackupFile = (byte) 0x01;
    public final byte fileTypeValueFile = (byte) 0x02;
    public final byte fileTypeLinearRecordFile = (byte) 0x03;
    public final byte fileTypeCyclicRecordFile = (byte) 0x04;

    // parsed data
    private byte[] dataFromResponse;
    private String fileTypeName;
    private boolean dataIsValid = false;

    public FileSettingRecordModel(byte fileNumber, byte[] dataFromResponse) {
        this.fileNumber = fileNumber;
        this.dataFromResponse = dataFromResponse;
        parseData();
    }

    private void parseData() {
        if (dataFromResponse == null) {
            dataIsValid = false;
            Log.e(TAG, "dataFromResponse is NULL, aborted");
            return;
        }
        // split up the data
        if (dataFromResponse.length != 13) {
            dataIsValid = false;
            Log.e(TAG, "dataFromResponse is not of length 13, found length " + dataFromResponse.length + ", aborted");
            return;
        }
        fileType = dataFromResponse[0];
        communicationSettings = dataFromResponse[1];
        accessRightRwCar = dataFromResponse[2];
        accessRightRW = dataFromResponse[3];
        recordSizeByte = Arrays.copyOfRange(dataFromResponse, 4, 7);
        maxRecordsByte = Arrays.copyOfRange(dataFromResponse, 7, 10);
        recordsExistingByte = Arrays.copyOfRange(dataFromResponse, 10, 13);
        recordSize = byteArrayLength3InversedToInt(recordSizeByte);
        maxRecords = byteArrayLength3InversedToInt(maxRecordsByte);
        recordsExisting = byteArrayLength3InversedToInt(recordsExistingByte);
        // get human readable data
        byte fileTypeStandardFile = (byte) 0x00;
        byte fileTypeBackupFile = (byte) 0x01;
        byte fileTypeValueFile = (byte) 0x02;
        byte fileTypeLinearRecordFile = (byte) 0x03;
        byte fileTypeCyclicRecordFile = (byte) 0x04;
        if (fileType == fileTypeStandardFile) {
                fileTypeName = "Standard file";
            } else if (fileType == fileTypeBackupFile) {
            fileTypeName = "Backup file";
        } else if (fileType == fileTypeValueFile) {
            fileTypeName = "Value file";
        } else if (fileType == fileTypeLinearRecordFile) {
            fileTypeName = "Linear record file";
        } else if (fileType == fileTypeCyclicRecordFile) {
            fileTypeName = "Cyclic record file";
        } else {
            fileTypeName = "unknown file type";
        }
        // todo human readable data for communication settings and access right settings
        dataIsValid = true;
    }

    public byte getFileType() {
        return fileType;
    }

    public byte getFileNumber() {
        return fileNumber;
    }

    public byte getCommunicationSettings() {
        return communicationSettings;
    }

    public byte getAccessRightRwCar() {
        return accessRightRwCar;
    }

    public byte getAccessRightRW() {
        return accessRightRW;
    }

    public byte[] getRecordSizeByte() {
        return recordSizeByte;
    }

    public byte[] getMaxRecordsByte() {
        return maxRecordsByte;
    }

    public byte[] getRecordsExistingByte() {
        return recordsExistingByte;
    }

    public int getRecordSize() {
        return recordSize;
    }

    public int getMaxRecords() {
        return maxRecords;
    }

    public int getRecordsExisting() {
        return recordsExisting;
    }

    public byte getFileTypeStandardFile() {
        return fileTypeStandardFile;
    }

    public byte getFileTypeBackupFile() {
        return fileTypeBackupFile;
    }

    public byte getFileTypeValueFile() {
        return fileTypeValueFile;
    }

    public byte getFileTypeLinearRecordFile() {
        return fileTypeLinearRecordFile;
    }

    public byte getFileTypeCyclicRecordFile() {
        return fileTypeCyclicRecordFile;
    }

    public byte[] getDataFromResponse() {
        return dataFromResponse;
    }

    public String getFileTypeName() {
        return fileTypeName;
    }

    public boolean isDataIsValid() {
        return dataIsValid;
    }

    // returns the file size related data
    public String dumpFileSizes() {
        StringBuilder sb = new StringBuilder();
        sb.append("data for file number ").append(fileNumber).append(" of type ").append(fileType).append(" (").append(fileTypeName).append(")").append("\n");
        sb.append("record size: ").append(recordSize).append("\n");
        sb.append("max. number of records: ").append(maxRecords).append("\n");
        sb.append("number of existing records: ").append(recordsExisting).append("\n");
        return sb.toString();
    }

    private int byteArrayLength3InversedToInt(byte[] data) {
        return (data[2] & 0xff) << 16 | (data[1] & 0xff) << 8 | (data[0] & 0xff);
    }

    private int byteArrayLength3NonInversedToInt(byte[] data) {
        return (data[0] & 0xff) << 16 | (data[1] & 0xff) << 8 | (data[2] & 0xff);
    }
}
