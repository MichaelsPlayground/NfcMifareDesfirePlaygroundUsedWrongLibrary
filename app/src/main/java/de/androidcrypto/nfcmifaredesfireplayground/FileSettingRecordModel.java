package de.androidcrypto.nfcmifaredesfireplayground;

import android.util.Log;

public class FileSettingRecordModel {

    private static final String TAG = "FileSettingRecordModel";
    private byte fileType; // 04 for record based files see DESFire EV protocol
    private byte fileNumber;
    private byte communicationSettings;
    private byte accessRightRwCar;
    private byte accessRightRW;
    private byte[] recordSizeByte; // 3 bytes
    private byte[] maxRecordsByte; // 3 bytes
    private byte[] recordsExistingByte; // 3 bytes
    private int recordSize;
    private int maxRecords;
    private int recordsExisting;
    private byte[] dataFromResponse;
    private boolean dataIsValid = false;

    public FileSettingRecordModel(byte[] dataFromResponse) {
        this.dataFromResponse = dataFromResponse;
        analyzeData();
    }

    private void analyzeData() {
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
        fileNumber = dataFromResponse[1];
        communicationSettings = dataFromResponse[2];
        accessRightRwCar = dataFromResponse[3];
        accessRightRW = dataFromResponse[4];

    }
}
