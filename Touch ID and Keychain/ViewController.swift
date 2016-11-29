//
//  ViewController.swift
//  Key Chain Test
//
//  Created by David Gatti on 11/27/16.
//  Copyright © 2016 David Gatti. All rights reserved.
//

// https://www.cigital.com/blog/integrating-touch-id-into-ios-applications/
// https://developer.apple.com/reference/security/1658642-keychain_services
// https://developer.apple.com/library/content/samplecode/KeychainTouchID/Introduction/Intro.html

import UIKit
import LocalAuthentication

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
		
		//
		//	Check if the device the code is running on is capapble of 
		//	finger printing.
		//
        let dose_it_can = LAContext()
			.canEvaluatePolicy(
				.deviceOwnerAuthenticationWithBiometrics, error: nil);
        
        if(dose_it_can)
        {
			print("Yes it can");
        }
        else
        {
			print("No it can't");
        }
        
		//
		//	Show the Touch ID dialog to check if we can get a print from 
		//	the user
		//
        LAContext().evaluatePolicy(
			LAPolicy.deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "dsds",
            reply: {
				(status: Bool, evaluationError: Error?) -> Void in
									
				if(status)
				{
					print("OK");
				}
				else
				{
					print("Not OK");
				}
				
		});
		
        // INSERT ////////////////////////////////////////////////////////////
        
        //
        //  Secret value to store
        //
        let valueData = "The Top Secret Message V1".data(using: .utf8)!;
        
        let sacObject =
			SecAccessControlCreateWithFlags(kCFAllocatorDefault,
								kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                .userPresence,
                                nil);
        
        //
        //  Create the Key Value array, that holds the query to store 
        //  our data
        //
        let insert_query: NSDictionary = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccessControl: sacObject!,
            kSecValueData: valueData,
            kSecUseAuthenticationUI: kSecUseAuthenticationUIAllow,
            //	This two valuse ideifieis the entry, together they become the
			//	primary key in the Database
            kSecAttrService: "app_name",
            kSecAttrAccount: "first_name"
        ];
        
        //
        //  Execute the query to add our data to Keychain
        //
        let resultCode = SecItemAdd(insert_query as CFDictionary, nil);
        
        //
        //  Check if there was an error with our query
        //
        if(resultCode != noErr)
        {
            print("INSERT Error: \(resultCode).");
        }
        else
        {
            print("Saved successfully.");
        }
        
        // SELECT ////////////////////////////////////////////////////////////
        
        //
        //  Create the Key Value array that holds our qury to retive our
        //  secret data.
        //
        let select_query: NSDictionary = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "app_name",
            kSecAttrAccount: "first_name",
            kSecReturnData: true,
            kSecUseOperationPrompt: "sdsd"
        ];
        
        //
        //
        //
        var extractedData: AnyObject?;
        
        //
        //  Execute our query to get our data back
        //
        let status = SecItemCopyMatching(select_query, &extractedData);
        
        //
        //  If the result was positive, we display our data
        //
        if(status != noErr)
        {
            print("SELECT Error: \(resultCode).");
        }
        else
        {
            let retrievedData = extractedData as? NSData;
            
            let ble = String(data: retrievedData as! Data, encoding: .utf8);
            
            print(ble!);
        }
        
        // UPDATE ////////////////////////////////////////////////////////////
        
        //
        //  Create the Key Value array, that holds the query to store
        //  our data
        //
        let update_query: NSDictionary = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "app_name",
            kSecAttrAccount: "first_name",
            kSecReturnData: false
        ];
		
		//
		//  Secret value to store
		//
		let updated_data = "The Top Secret Message V2".data(using: .utf8)!;
		
		//
		//	New data
		//
        let data: NSDictionary = [
            kSecAttrAccount: "first_name",
            kSecValueData: updated_data
        ];
        
        //
        //  Execute the query to add our data to Keychain
        //
        let update_result = SecItemUpdate(update_query, data)
        
        //
        //  Check if there was an error with our query
        //
        if(update_result != noErr)
        {
            print("UPDATE Error: \(resultCode).");
        }
        else
        {
            print("Updated successfully.");
        }
        
        // SELECT /////////////////////////////////////////////////////////////
        
        //
        //  Create the Key Value array that holds our qury to retive our
        //  secret data.
        //
        let select_query2: NSDictionary = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "app_name",
            kSecAttrAccount: "first_name",
            kSecReturnData: true
        ];
        
        //
        //
        //
        var extractedData2: AnyObject?;
        
        //
        //  Execute our query to get our data back
        //
        let status2 = SecItemCopyMatching(select_query2, &extractedData2);
        
        //
        //  If the result was positive, we display our data
        //
        if(status2 != noErr)
        {
            print("SELECT Error: \(resultCode).");
        }
        else
        {
            let retrievedData = extractedData2 as? NSData;
            
            let ble = String(data: retrievedData as! Data, encoding: .utf8);
            
            print(ble!);
        }
        
        // DELETE ////////////////////////////////////////////////////////////
        
        //
        //  Create the Key Value array that holds our qury to retive our
        //  secret data.
        //
        let delete_query: NSDictionary = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "app_name",
            kSecAttrAccount: "first_name",
            kSecReturnData: false
        ];
        
        //
        //  Execute our query to get our data back
        //
        let delete_status = SecItemDelete(delete_query);
        
        //
        //  If the result was positive, we display our data
        //
        if(delete_status != noErr)
        {
            print("DELETE Error: \(resultCode).");
        }
        else
        {
            print("Deleted successfully.");
        }
    }
}

