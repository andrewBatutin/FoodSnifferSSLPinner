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
        let url = Bundle.main.url(forResource: "dropboxcom", withExtension: "crt")!
        let data = try! Data(contentsOf: url)
        return [data]
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
        
        print("being challanged! for \(challenge.protectionSpace.host)")
        
        guard let trust = challenge.protectionSpace.serverTrust else {
            print("invalid trust!")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        
        let credential = URLCredential(trust: trust)
        
        
        if (validateTrustPublicKeys(trust)) {
            completionHandler(.useCredential, credential)
            
        } else {
            print("couldn't validate trust for \(challenge.protectionSpace.host)")
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
    
    func validateTrustPublicKeys(_ trust:SecTrust) -> Bool{
        return false
    }
}

