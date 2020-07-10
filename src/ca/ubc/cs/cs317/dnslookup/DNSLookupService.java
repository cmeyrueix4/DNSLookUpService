package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.io.IOException;
import java.net.*;
import java.util.*;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();

    private static InetAddress nameServer;
    private static int anCount = 0;
    private static int nsCount = 0;
    private static int arCount = 0;
    private static boolean authority = false;
    private static boolean badRcode = false;
    private static int timeoutCount = 0;

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                anCount = 0;
                authority = false;
                badRcode = false;

                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {
        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {
        //Ensure IndirectionLevel hasn't been exceeded
        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        //Reset global variables in case of recursive call
        anCount = 0;
        authority = false;
        badRcode = false;

        //Update nameserver in case of recursive call
        nameServer = rootServer;

        // return the answer if in cachedRRs
        Set<ResourceRecord> cachedRRs = cache.getCachedResults(node);
        if (!cachedRRs.isEmpty()){
            return cachedRRs;
        }

        //Initialize set to be returned
        Set<ResourceRecord> finalResults = new HashSet<>();

        //While an answer has not been found && authoritative is false && rcode is valid keep looking for an answer
        while(anCount == 0 && authority == false && badRcode == false){
            // CNAME not in cache yet
            if (cache.getCachedResults(node).isEmpty()) {
                // update rrs

                if (nameServer != null) {
                    // retrieveResults updates the nameServer
                    retrieveResultsFromServer(node, nameServer);
                    cachedRRs = cache.getCachedResults(node);

                }
            } else {
                break;
            }
        }

        //Handle CNAME case
        if (anCount > 0 && authority == true){
            //Create CNAME node to determine if we have cached it
            DNSNode CNAME = new DNSNode(node.getHostName(), RecordType.CNAME);

            //Create dnsNode to determine is it has already been cached
            DNSNode dnsNode = new DNSNode(node.getHostName(), node.getType());

            //Get the caches for both of the above nodes
            cachedRRs = cache.getCachedResults(CNAME);
            Set<ResourceRecord> cachedRRAs = cache.getCachedResults(dnsNode);

            //Iterate through CNAME cache
            for (ResourceRecord rr : cachedRRs){
                //Recursive call to getResults if rr is a CNAME
                if (rr.getType() == RecordType.CNAME){
                    DNSNode CnameNode = new DNSNode(rr.getTextResult(), node.getType());
                    finalResults.addAll(getResults(CnameNode, indirectionLevel + 1));
                } else if(rr.getType() == RecordType.A){
                    finalResults.add(rr);
                }

            }

            //Iterate through node's cache (Non-CNAME)
            for(ResourceRecord rr: cachedRRAs){
                finalResults.add(rr);
            }

        }

        //Add the finalResults found to the cache with proper fields. Mostly handles the AAAA case
        if (cache.getCachedResults(node).isEmpty()) {
            for (ResourceRecord rr : finalResults) {
                cache.addResult(new ResourceRecord(node.getHostName(), node.getType(), rr.getTTL(), rr.getTextResult()));
            }
        }

        return finalResults;
    }




    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        //Create a query out of the given DNSNode
        Query query = new Query(node);

        //Encode it in order to send it to server
        byte[] buf = query.encodeQuery(node);

        //Create Datagram and try to send it to the socket
        DatagramPacket sendPacket = new DatagramPacket(buf, buf.length,
                server, DEFAULT_DNS_PORT);

        try {
            socket.send(sendPacket);
        } catch (IOException e) {
            e.printStackTrace();
        }

        //Set up the array for the socket response and attempt to receive response from socket
        byte[] response = new byte[1024];
        DatagramPacket receivePacket = new DatagramPacket(response, response.length);
        try {
            socket.receive(receivePacket);
        } catch (SocketTimeoutException e) {
            timeoutCount++;
        }catch (IOException e) {
            timeoutCount++;
            return;
        }



        //Get response data
        byte[] responseBuff = receivePacket.getData();

        //Get Set of decoded RR's

        Set<ResourceRecord> results = query.decodeQuery(responseBuff);

        //If trace is on then send the decoded results to get printed
        if(verboseTracing){
            byte[] header = Arrays.copyOfRange(response, 0, query.getHeader().length);
            int[] traceOn = query.decodeHeader(header);


            printTraceRoute(traceOn, node, results);

        }

        //Update global variables for recursive call
        anCount = query.getAnCount();
        nsCount = query.getNsCount();
        arCount = query.getArCount();
        badRcode = query.getRcode();


        //Initialize current RR and randomize the selection for search
        ResourceRecord current = null;
        if(nsCount > 0) {
            Random rand = new Random();
            int random = rand.nextInt(nsCount);
            Object[] arrayCurr = results.toArray();
            current = (ResourceRecord) arrayCurr[random];
        }


        //Iterate through decoded RR's
        for (ResourceRecord rr: results) {
            //If additional count is greater than 0 than find the one that corresponds to the randomly selection NS
            if (arCount > 0) {
                if (rr.getType().getCode() == 1) {
                    if(current != null) {
                        if (rr.getHostName().equals(current.getTextResult())) {
                            nameServer = rr.getInetResult();
                            break;
                        }
                    } else {
                        nameServer = rr.getInetResult();
                        break;
                    }

                }
            }
            //If there are no answers then get the results of an NS query
            else if(arCount == 0 && anCount == 0) {
                nameServer = rootServer;
                Set<ResourceRecord> cached = cache.getCachedResults(new DNSNode(rr.getTextResult(), RecordType.A));
                if(!cached.isEmpty()){
                    for(ResourceRecord ca: cached){
                        if(ca.getType() == RecordType.A){
                            nameServer = ca.getInetResult();
                            break;
                        }
                    }
                } else {
                    Set<ResourceRecord> res = getResults(new DNSNode(rr.getTextResult(), RecordType.A), 0);
                    if (!res.isEmpty()){
                        Object[] arrayCurr = res.toArray();
                        ResourceRecord curr = (ResourceRecord) arrayCurr[0];
                        nameServer = curr.getInetResult();
                        break;
                    }
                }
            }
        }

        //Update global variables for recursive call
        authority = query.getAuthority();
        anCount = query.getAnCount();
        nsCount = query.getNsCount();
        arCount = query.getArCount();
        badRcode = query.getRcode();
    }

    /**
     * Print the trace route
     * @param traceOn Header array from decodeHeader functions
     * @param node current DNSNode
     * @param recordSet set of RRs
     */
    private static void printTraceRoute(int[] traceOn, DNSNode node, Set<ResourceRecord> recordSet){
        //Authoritative response
        Boolean auth = (traceOn[1] > 0);
        Iterator value = recordSet.iterator();

        System.out.println();
        System.out.println();

        System.out.println("Query ID     " + traceOn[0] + " " + node.getHostName() + "  " + node.getType() + " --> " + nameServer.getHostAddress());
        System.out.println("Response ID: " + traceOn[0] + " Authoritative = " + auth);
        System.out.println("  Answers (" + traceOn[2] + ")");

        //initialize curr to work with the Set Iterator
        ResourceRecord curr = null;

        //If there are answers print them
        if(traceOn[2] > 0){
            while(value.hasNext()){
                curr = (ResourceRecord) value.next();
                if(curr.getType() == RecordType.NS){
                    break;
                }
                verbosePrintResourceRecord(curr, curr.getType().getCode());
            }
        }

        System.out.println("  Nameservers (" + traceOn[3] + ")");
        if(traceOn[3] > 0){
            if (curr !=null){
                verbosePrintResourceRecord(curr, curr.getType().getCode());
            }
            while(value.hasNext()){
                curr = (ResourceRecord) value.next();
                if(curr.getType() == RecordType.A || curr.getType() == RecordType.AAAA){
                    break;
                }
                verbosePrintResourceRecord(curr, curr.getType().getCode());
            }
        }

        System.out.println("  Additional Information (" + traceOn[4] + ")");
        if(traceOn[4] > 0){
            if (curr !=null){
                verbosePrintResourceRecord(curr, curr.getType().getCode());
            }
            while(value.hasNext()){
                curr = (ResourceRecord) value.next();
                if(curr.getType() == RecordType.NS){
                    break;
                }
                verbosePrintResourceRecord(curr, curr.getType().getCode());
            }
        }

    }

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }
}