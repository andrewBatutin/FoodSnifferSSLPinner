//
//  FoodListAPIConsumer.swift
//  FoodSniffer
//
//  Created by andrew batutin on 7/3/18.
//  Copyright © 2018 HomeOfRisingSun. All rights reserved.
//

import Foundation
import Security

enum DataResult{
    case Empty(Error)
    case Full([FoodItem])
}

enum DaySegments:String,Codable{
    
    case morning
    case afternoon
    case evening
    
}

struct FoodItem:Codable {
    
    let name:String
    let consumePeriod:DaySegments
    
}

@objc
final class FoodListAPIConsumer : NSObject, URLSessionDelegate{
    
    let certificates: [Data] = {
        let certList = ["dropboxcom", "dldropboxusercontentcom"]
        let result = certList.map({ (certName) -> Data in
            let url = Bundle.main.url(forResource: certName, withExtension: "crt")!
            let certData =  try! Data(contentsOf: url)
            return certData
        })
        return result
    }()
    
    let foodListURL = "https://www.dropbox.com/s/8ipgua5mfiakhxy/MockFoodListJSON.json?dl=1"
    
    
    func loadFoodList(_ callback: @escaping ( DataResult ) -> ()){
        
        guard let foodUrl = URL(string: foodListURL) else { return }
        let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        let dataTask = session.dataTask(with: foodUrl) { (data, response, error) in
            
            if let networkError = error {
                print(networkError.localizedDescription)
                DispatchQueue.main.async {
                    callback(DataResult.Empty(networkError))
                }
                return
            }
            
            guard let foodData = data else {
                DispatchQueue.main.async {
                    callback(DataResult.Full([]))
                }
                return
            }
            
            let decoder = JSONDecoder()
            do{
                let items = try decoder.decode([FoodItem].self, from: foodData)
                DispatchQueue.main.async {
                    callback(DataResult.Full(items))
                }
            }catch{
                print(error)
                DispatchQueue.main.async {
                    callback(DataResult.Empty(error))
                }
                return
            }
            
        }
        dataTask.resume()
    }
    
}


extension FoodListAPIConsumer {
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        let credential = URLCredential(trust: trust)
        
        if (validateTrustCertificateList(trust)) {
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
    
    func validateTrustCertificateList(_ trust:SecTrust) -> Bool{
        
        for index in 0..<SecTrustGetCertificateCount(trust) {
            if let certificate = SecTrustGetCertificateAtIndex(trust, index){
                let serverCertificateData = SecCertificateCopyData(certificate) as Data
                if ( certificates.contains(serverCertificateData) ){
                    return true
                }
            }
        }
        
        return false
    }
}

