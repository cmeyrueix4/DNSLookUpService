package ca.ubc.cs.cs317.dnslookup;import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Query {
    byte[] header;
    byte[] question;
    byte[] answer;
    byte[] auth;
    byte[] additional;
    int startPoint = 0;
    private static DNSCache cache = DNSCache.getInstance();

    public int ANCount;
    public int NSCount;
    public int ARCount;
    public boolean authority;
    public boolean badRcode;


    /**
     * Create a Query that build the Header and Question given a DNSNode
     * @param node
     */
    public Query(DNSNode node) {
        this.header = buildHeader();
        this.question = buildQuestion(node);
    }

    /**
     * Creates the header for the query
     *
     * @return Byte array of length 12 for the header of the query
     */
    private byte[] buildHeader() {
        //Create different sections
        byte[] queryID = new byte[2];
        new Random().nextBytes(queryID);
        byte[] qrAndZ = new byte[2];
        byte[] qdCount = new byte[2];
        qdCount[1] = 01;
        byte[] anCount = new byte[2];
        byte[] nsCount = new byte[2];
        byte[] arCount = new byte[2];

        //Add to all created sections to a buffer
        ByteBuffer buff = ByteBuffer.wrap(new byte[12]);
        buff.put(queryID);
        buff.put(qrAndZ);
        buff.put(qdCount);
        buff.put(anCount);
        buff.put(nsCount);
        buff.put(arCount);

        //Create array for header out of buffer
        byte[] header = buff.array();

        return header;

    }


    /**
     * Creates the question for the query
     *
     * @param node Fully qualified domain name server being searched.
     *
     * @return Byte array of variable length (depends on the lookup name)
     *         for the question section of the query
     */
    private byte[] buildQuestion(DNSNode node) {

        //Get DNSNode information for building a Questions
        String hostName = node.getHostName();
        int type = node.getType().getCode();

        byte labelLen;
        byte[] labelVal;

        //Split sections of name host to later encode it
        String[] nameLabels = hostName.split("\\.");

        //Identify the total number of sections
        int totalSectionLen = nameLabels.length + 5;


        for (String s: nameLabels) {
            totalSectionLen += s.length();
        }

        ByteBuffer buff = ByteBuffer.wrap(new byte[totalSectionLen]);

        //Convert the host name sections to bytes
        for (int i = 0; i < nameLabels.length ; i++) {
            labelLen = Integer.valueOf(nameLabels[i].length()).byteValue();
            labelVal = nameLabels[i].getBytes(StandardCharsets.US_ASCII);

            buff.put(labelLen);
            buff.put(labelVal);

        }

        //Create question sections
        byte[] nullLabel = new byte[1];
        byte[] qType = new byte[2];
        qType[1] = (byte)type;
        byte[] qClass = new byte[2];
        qClass[1] = 01;

        buff.put(nullLabel);
        buff.put(qType);
        buff.put(qClass);

        //Put everything into a byte array
        byte[] question = buff.array();

        return question;

    }

    /**
     * Encode query to send to server
     *
     * @return Byte array of the send-query for the datagram packet
     */
    public byte[] encodeQuery(DNSNode node){
        byte[] sHeader = buildHeader();
        byte[] sQuestion = buildQuestion(node);

        ByteBuffer buff = ByteBuffer.wrap(new byte[sHeader.length + sQuestion.length]);
        buff.put(sHeader);
        buff.put(sQuestion);

        return buff.array();
    }

    /**
     * Decode query received from server, sets the fields of the class:
     * header, question, answer, auth, additional
     *
     * @param response, byte array of the response from server
     * @return Set<ResourceRecord>, returns a set of decoded resource records
     */
    public Set<ResourceRecord> decodeQuery(byte[] response){
        //Create result Set. Used a LinkedHashSet in order to maintain insertion order
        Set<ResourceRecord> results = new LinkedHashSet<>();

        //Separate Header section to decode it
        byte[] header = Arrays.copyOfRange(response, 0, this.header.length);
        int[] ansCount = decodeHeader(header);

        //Initialize start point variable which will keep track of the beginning of each RR.
        //First initialization is after the question and header
        startPoint = this.header.length + this.question.length;

        //Create variables to identify number of each type of RR
        int authorityCount = ansCount[3];
        int additionalCount = ansCount[4];
        int answerCount = ansCount[2];

        //Send each type of RR into the decode ResourceRecord
        while(answerCount > 0){
            ResourceRecord answer = decodeResourceRecord(response);
            answerCount--;

            //Add answer to result Set
            results.add(answer);

            //Add answer to cache
            cache.addResult(answer);
        }

        while(authorityCount > 0){
            ResourceRecord authority = decodeResourceRecord(response);
            authorityCount--;

            //Add Nameserver to result Set
            results.add(authority);
        }

        while(additionalCount > 0){
            ResourceRecord additional = decodeResourceRecord(response);
            additionalCount--;

            //Add Additional to result Set
            results.add(additional);

            //Cache additional result
            cache.addResult(additional);
        }


        return results;
    }


    /**
     * Decode header response
     * @param header
     * @return Array of values that identify the results of the Header to be used in DNSLookupService
     */
    public int[] decodeHeader(byte[] header) {
        //Get each Header section to later decode
        byte[] queryID = Arrays.copyOfRange(header, 0, 2);
        byte[] qrAndZ = Arrays.copyOfRange(header, 2, 4);
        byte[] qdCount = Arrays.copyOfRange(header, 4, 6);
        byte[] anCount = Arrays.copyOfRange(header, 6, 8);
        byte[] nsCount = Arrays.copyOfRange(header, 8, 10);
        byte[] arCount = Arrays.copyOfRange(header, 10, 12);

        //Set global variables to keep track of the count of each type of RR
        ANCount = anCount[0] + anCount[1];
        NSCount = nsCount[0] + nsCount[1];
        ARCount = arCount[0] + arCount[1];

        //Ensure non-error rCode
        int rCode = (qrAndZ[1] & 0x0F);
        if (rCode == 3 || rCode == 5) {
            badRcode = true;
        }


        //Get Question ID
        StringBuilder qID = new StringBuilder();
        for (byte b : queryID) {
            qID.append(String.format("%02X", b));
        }
        String id = qID.toString();
        int quId = new BigInteger(id, 16).intValue();

        //Get Authority value
        int auth = (qrAndZ[0] & 0x0F) >>> 2;
        authority = (auth == 1);

        //Return an array of values to use in DNSLookUp Service
        int[] returnArray = new int[5];
        //Add QID
        returnArray[0] = quId;

        //Add authorty value
        returnArray[1] = auth;

        //Add Answer Count value
        returnArray[2] = anCount[1]+anCount[0];

        //Add Nameserver count value
        returnArray[3] = nsCount[1]+nsCount[0];

        //Add Additional count value
        returnArray[4] = arCount[1]+arCount[0];

        return returnArray;
    }

    /**
     * Decodes the ResourceRecord
     *
     * @param response array to be decoded
     * @return ResourceRecord to be added to result set in decodeQuery()
     */
    private ResourceRecord decodeResourceRecord(byte[] response) {
        //Initialize RR to be returned
        ResourceRecord curr = null;

        //Get sections of RR
        byte[] rrs = Arrays.copyOfRange(response, startPoint, response.length);
        byte[] namePtr = Arrays.copyOfRange(rrs, 0, 2);

        //Identify where name is pointing to, if it is a pointer
        int offset = 0;
        if (pointerOffset(namePtr) != 0){
            offset = pointerOffset(namePtr);
        }

        byte[] type = Arrays.copyOfRange(rrs, 2, 4);
        byte[] rrclass = Arrays.copyOfRange(rrs, 4, 6);
        byte[] ttl = Arrays.copyOfRange(rrs, 6, 10);
        byte[] rdLength = Arrays.copyOfRange(rrs, 10, 12);

        int length = 12;
        String host = "";
        if(offset == 0){
            int currbound = rrs[offset];
            namePtr = Arrays.copyOfRange(rrs, offset, currbound);
            host = decodePointerHost(offset, rrs);
            int lengthHost = host.length()+1;

            type = Arrays.copyOfRange(rrs, lengthHost+1, lengthHost + 3);
            rrclass = Arrays.copyOfRange(rrs, lengthHost + 3, lengthHost+5);
            ttl = Arrays.copyOfRange(rrs, lengthHost+5, lengthHost+9);
            rdLength = Arrays.copyOfRange(rrs, lengthHost+9, lengthHost+11);
            length = lengthHost +11;
        }

        //Get length of RData
        int rdlen = rdLength[1] + rdLength[0];

        //Get type of RR
        int typeDecode = type[0] + type[1];
        RecordType recordType = RecordType.getByCode(typeDecode);

        //Get TTL of RR
        long newTTL = getNewTTL(ttl);

        //Get RData based on rdLength
        byte[] rData = Arrays.copyOfRange(rrs, length, length+rdlen);

        //Update startpoint variable to be after the end of RData
        startPoint += (length+rdlen);


        //Initialize newHost variable which will have the result of the hosts found in the RR
        String newHost = "";
        if(recordType != RecordType.A && recordType != RecordType.AAAA){
            //Send rData to decode to find newHost
            newHost = decodeRdataAuthority(rData, response);

            //If the offset is pointing to a pointer, update offset
            offset = checkIfPointer(offset, response);

            //Decode the host the offset is pointing to
            String oldHost;
            if(host.equals("")){
                oldHost = decodePointerHost(offset, response);
            } else {
                oldHost = host;
            }

            //Update curr RR to be returned
            curr = new ResourceRecord(oldHost, recordType, newTTL, newHost);
        } else if(recordType == RecordType.A|| recordType == RecordType.AAAA){
            //Send rData to decode to find IP address
            InetAddress ip = decodeRdataAdditional(rData);

            //If the offset is pointing to a pointer, update offset
            offset = checkIfPointer(offset, response);

            //Decode the host the offset is pointing to
            String oldHost;
            if(host.equals("")){
                oldHost = decodePointerHost(offset, response);
            } else {
                oldHost = host;
            }

            //Update curr RR to be returned
            curr = new ResourceRecord(oldHost, recordType, newTTL, ip);
        }

        return curr;
    }

    /**
     * Identify if offset is a pointer to a pointer
     *
     * @param offset current offset to be indexed
     * @param response array to find new pointer if offset is a pointer to a pointer
     * @return new offset
     */
    private int checkIfPointer(int offset, byte[] response) {
        //if response[offset] is < 0 then it is pointing to a pointer and must be updated
        while (response[offset] < 0) {
            byte[] temp = new byte[2];
            temp[0] = response[offset];
            temp[1] = response[offset + 1];
            int offsetResult = pointerOffset(temp);
            if (offsetResult > response.length) {
                return offset;
            } else {
                if (offset != 0){
                    offset = offsetResult;
                } else {return offset;}
            }
        }

        return offset;
    }


    /**
     * Gets the TTL of an RR
     *
     * @param ttl
     * @return long for the ttl
     */
    private long getNewTTL(byte[] ttl) {
        StringBuilder sii = new StringBuilder();
        for (byte b : ttl) {
            sii.append(String.format("%02X", b));

        }
        String s = sii.toString();
        return new BigInteger(s, 16).longValue();
    }

    /**
     * Decode A and AAAA records to find the InetAddress
     *
     * @param rData
     * @return InetAddress
     */
    private InetAddress decodeRdataAdditional(byte[] rData){
        InetAddress finalAddress = null;

        try {
            finalAddress = InetAddress.getByAddress(rData);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        return finalAddress;
    }

    /**
     *
     * Decodes Rdata for Resource Record that is Authority Type
     * @param rData
     * @return new hostName
     */
    private String decodeRdataAuthority(byte[] rData, byte[] response){
        //Initialize empty hostname string
        String newHostName = "";

        //Handle case where RData is a pointer
        if(pointerOffset(rData)!=0){
            newHostName = decodePointerHost(pointerOffset(rData), response);
            return newHostName;
        }

        //Grab number of bytes to convert in this section
        int currBound = rData[0];

        //Iterate through the host name sections and update bound until a pointer is reached
        for(int i = 1; i < rData.length; i++){
            currBound--;

            //Grab Byte to convert to string
            byte[] currByte = new byte[1];
            currByte[0] = rData[i];

            //Attempt to convert byte into a ASCII string
            String letter = "";
            try {
                letter = new String(currByte, "UTF-8");
            } catch (Exception e){
                System.out.println(e);
            }

            //Append new letter to hostname
            newHostName = newHostName + letter;

            //When currBound reaches 0, update the bound to the next part of host name or break if a pointer is reached
            if(currBound == 0){
                int offset;
                offset = pointerOffset(Arrays.copyOfRange(rData, i+1, rData.length));
                if(offset != 0){
                    String pointerHostName = decodePointerHost(offset, response);
                    newHostName = newHostName + "." + pointerHostName;
//                    System.out.println("Final output = " + newHostName);
                    return newHostName;
                }

                //Update currbound for new section
                currBound = rData[i+1];

                //if the next bound is 0 then we have reached the end of the hostname
                if(currBound == 0) {
                    return newHostName;
                }

                //Add the "." to hostname
                newHostName = newHostName + ".";

                //Increment i to the next byte to convert to string
                i++;
            }
        }

        return newHostName;
    }


    /**
     * Decodes the pointer held in a Resource Record Rdata
     * @param offset pointer
     * @param response array to be decoded
     * @return hostName of the pointer type
     */
    private String decodePointerHost(int offset, byte[] response){
        //Grab number of bytes to convert
        int currBound = response[offset];


        //Initialize empty hostname string
        String newHostName = "";

        //Iterate through the host name sections and update bound until a pointer is reached
        for(int i = offset+1; i < response.length; i++){
            currBound--;

            //Grab Byte to convert to string
            byte[] currByte = new byte[1];
            currByte[0] = response[i];

            //Attempt to convert byte into a ASCII string
            String letter = "";
            try {
                letter = new String(currByte, "UTF-8");
            } catch (Exception e){
                System.out.println(e);
            }

            //Append new letter to hostname
            newHostName = newHostName + letter;

            //When currBound reaches 0, update the bound to the next part of host name or break if a pointer is reached
            if(currBound == 0){
                if(response[i+1] == 0){
                    break;
                }

                //Find out if the pointer is pointing to another pointer, if it is decode the result of new pointer
                int innerOffset = pointerOffset(Arrays.copyOfRange(response, i+1, i+3));
                if (innerOffset != 0){
                    String ptrHostName = decodePointerHost(innerOffset, response);
                    newHostName = newHostName + "." + ptrHostName;
                    break;
                }

                //Update current bound to new section
                currBound = response[i+1];

                //if the next bound is 0 then we have reached the end of the hostname
                if(currBound == 0) {
                    return newHostName;
                }

                //Add the "." to hostname
                newHostName = newHostName + ".";

                //Increment i to the next byte to convert to string
                i++;
            }
        }
        return newHostName;
    }


    //Checks to see if its a pointer

    /**
     * Checks to see if the bytes are a pointer and converts it to proper index
     * @param bytes
     * @return offset for pointer
     */
    private int pointerOffset(byte[] bytes){
        int firstTwoBits = (bytes[0] & 0xF0) >>> 6;

        if (firstTwoBits == 0x3) {
            int lastTwoBits = ((bytes[0] & 0x0F) << 8);
            int offset = lastTwoBits + (bytes[1] & 0xFF);
            return offset;
        }
        else {
            return 0;
        }

    }

    public byte[] getHeader(){
        return this.header;
    }

    public int getAnCount(){
        return ANCount;
    }

    public int getNsCount(){
        return NSCount;
    }

    public int getArCount(){
        return ARCount;
    }

    public boolean getAuthority(){
        return authority;
    }

    public boolean getRcode(){
        return badRcode;
    }
}