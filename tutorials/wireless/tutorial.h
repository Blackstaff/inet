/**
@mainpage Wireless Tutorial for the INET framework

In this tutorial, we show you how to build wireless simulations in the INET
framework. The tutorial contains a series of simulation models numbered from 1 through 19.
The models are of increasing complexity -- they start from the basics and
in each step, they introduce new INET features and concepts related to wireless communication
networks.

This is an advanced tutorial, and it assumes that you are familiar with creating
and running simulations in @opp and  INET. If you aren't, you can check out
the <a href="https://omnetpp.org/doc/omnetpp/tictoc-tutorial/"
target="_blank">TicToc Tutorial</a> to get started with using @opp. The <a
href="../../../doc/walkthrough/tutorial.html" target="_blank">INET Walkthrough</a>
is an introduction to INET and working with protocols.

If you need more information at any time, feel free to refer to the @opp and
INET documentation:

- <a href="https://omnetpp.org/doc/omnetpp/manual/usman.html" target="_blank">@opp User Manual</a>
- <a href="https://omnetpp.org/doc/omnetpp/api/index.html" target="_blank">@opp API Reference</a>
- <a href="https://omnetpp.org/doc/inet/api-current/inet-manual-draft.pdf" target="_blank">INET Manual draft</a>
- <a href="https://omnetpp.org/doc/inet/api-current/neddoc/index.html" target="_blank">INET Reference</a>

In the tutorial, each step is a separate configuration in the same omnetpp.ini file,
and consecutive steps mostly share the same networks, defined in NED.

@section contents Contents

- @ref step1
- @ref step2
- @ref step3
- @ref step4
- @ref step5
- @ref step6
- @ref step7
- @ref step8
- @ref step9
- @ref step10
- @ref step11
- @ref step12
- @ref step13

@nav{index,step1}

<!------------------------------------------------------------------------>

@page step1 Step 1 - Two hosts communicating wirelessly
PREV: <a href="index.html" class="el">Introduction</a>

@nav{index,step2}

@section s1goals Goals

In the first step, we want to create a network that contains two hosts,
with one host sending a UDP data stream wirelessly to the other. Our goal
is to keep the physical layer and lower layer protocol models as simple
and possible.

We'll make the model more realistic in later step.

@section s1model The model

In this step we use the model depicted below.

<img src="wireless-step1-v2.png">

The model contains a playground of the size 500x500 meters, with two hosts
spaced 400 meters apart. (The distance will be relevant in later steps.)

In INET, hosts are usually represented with the `StandardHost` NED type,
which is a generic template for TCP/IP hosts. It contains protocol
components like TCP, UDP and IP, slots for plugging in application models,
and various network interfaces (NICs). In this model, we configure the
hosts to use `UDPBasicApp` for UDP traffic generation, and
`IdealWirelessNic` for network interface.

As one can see, there are additional modules in the network. They are
responsible for tasks like visualization and configuring the IP layer.
We'll return to them in later steps, but for now we concentrate on the
module called `radioMedium`.

All wireless simulations in INET need a radio medium module. This module
represents the shared physical medium where communication takes place. It
is responsible for taking signal propagation, attenuation, interference,
and other physical phenomena into account.

INET can model the wireless physical layer at at various levels of detail,
realized with different radio medium modules. In this step, we use
`IdealRadioMedium`, which is the simplest model. It implements a variation
of unit disc radio, meaning that physical phenomena like signal attenuation
are ignored, and the communication range is simply specified in meters.
Transmissions within range are always correctly received unless collisions
occur. Modeling collisions (overlapping transmissions causing reception
failure) and interference range (a range where the signal cannot be
received correctly, but still collides with other signals causing their
reception to fail) are optional.

In this model, we turn off collisions and interference. Naturally, this model
of the physical layer has little correspondence to reality. However, it has its
uses in the simulation. Its simplicity and its consequent predictability are
an advantage in scenarios where realistic modeling of the physical layer is not
a primary concern, for example in the modeling of ad-hoc routing protocols.
Simulations using `IdealRadioMedium` also run faster than more realistic ones,
due to the low computational cost.

In hosts, network interface cards are represented by NIC modules. Radio is part of
wireless NIC modules. There are various radio modules, and one must always
use one that is compatible with the medium module. In this step, hosts contain
<tt>IdealRadio</tt> as part of IdealWirelessNic.

Here is the complete NED file that describes the above WirelessA network:

@dontinclude WirelessA.ned
@skip network WirelessA
@until hostB:
@skipline display
@skipline }

One can notice that in the source, hosts use the `INetworkNode` NED type
and not the promised `StandardHost`. This is because later steps will use
other NED types for hosts, so we leave host type is parameterizable
(`INetworkNode<` is the interface which all host types implement.). The
actual NED type is given in the `omnetpp.ini` file to be `StandardHost`.

@dontinclude omnetpp.ini
@skipline [Config Wireless01]
@until ####

-------------------

@dontinclude omnetpp.ini
@skipline .host*.wlan[*].typename = "IdealWirelessNic"

The most important parameter of <tt>IdealRadio</tt> is <i>communication range</i>.
<tt>IdealRadio</tt> receives a transmission correctly within communication
range, unless there is an interfering transmission.

@note This might seem overly simplified because such radios and signal propagation do not work
like that in real life. However, it can be very useful in modeling scenarios where
details of radio propagation is not of interest.

In this model, the communication range is set to 500m.

@dontinclude omnetpp.ini
@skipline *.host*.wlan[*].radio.transmitter.maxCommunicationRange = 500m

Interference (in this case, loss of packets due to collision) is also
modeled by <tt>IdealRadio</tt>. In this step, interference is turned off,
resulting in pairwise independent duplex communication channels.

@dontinclude omnetpp.ini
@skipline *.host*.wlan[*].radio.receiver.ignoreInterference = true

The radio data rates are set to 1 Mbps.

@dontinclude omnetpp.ini
@skipline **.bitrate = 1Mbps

Hosts in the network need IP addresses. IP address assignment in this model
is handled by an instance of <tt>IPv4NetworkConfigurator</tt>. This module
also sets up static routing between the hosts.

@dontinclude WirelessA.ned
@skip configurator:
@until @display
@skipline }

The hosts have to know each other's MAC addresses to communicate, which is
taken care of by using <i>GlobalARP</i>:

@dontinclude omnetpp.ini
@skipline **.arpType = "GlobalARP"

In the model, host A generates UDP packets which are received by host B.
To this end, host A contains a UDPBasicApp module, which generates 1000-byte UDP
messages at random intervals with exponential distribution, the mean of which is 10ms.
Therefore the app is going to generate 100 kbyte/s (800 kbps) UDP traffic (not counting protocol overhead).

@dontinclude omnetpp.ini
@skip *.hostA.numUdpApps = 1
@until *.hostA.udpApp[0].sendInterval = exponential(10ms)

Host B contains a <tt>UDPSink</tt> application that just discards received packets.

@dontinclude omnetpp.ini
@skip *.hostB.numUdpApps = 1
@until *.hostB.udpApp[0].localPort = 5000

The model also contains a gauge to display the number of packets received by Host B:

@dontinclude WirelessA.ned
@skipline @figure
@skipline moduleName

@section s1results Results

Here is an animation showing the hosts communicating:

<img src="step1_3_v5.gif">

When the simulation concludes at t=25s, the throughput instrument indicates that
around 2400 packets were sent. A packet with overhead is 1028 bytes, which means
the transmission rate was around 800 kbps.

<b>Number of packets received by host B: 2422</b>

Sources: @ref omnetpp.ini, @ref WirelessA.ned

@nav{index,step2}

<!------------------------------------------------------------------------>

@page step2 Step 2 - Setting up some animations

@nav{step1,step3}

@section s2goals Goals

Transmissions can be visualized in the simulation environment. The configuration
for this step will set up animations that show transmissions as they propagate
through space.

@section s2model The model

Steps in this tutorial build on each other. In omnetpp.ini, the configuration
<i>Wireless02</i> extends <i>Wireless01</i>.
This way, subsequent steps can be based on the previous ones by adding a
few lines to the .ini file.

@dontinclude omnetpp.ini
@skip [Config Wireless02]
@until extends

@dontinclude omnetpp.ini
@skipline [Config Wireless02]
@until ####

Visualizations are impemented by the <tt>Visualizer</tt> module.

Visualization of transmissions are enabled by editing the ini file:

@dontinclude omnetpp.ini
@skipline visualizer

This displays transmissions as colored rings emanating from hosts. Since this
is sufficient to represent transmissions visually, it is advisable to turn off
<i>animate messages</i> in qtenv.

In order to get a smooth animation, canvas updates have to be enabled and an
update interval has to be set:

@dontinclude omnetpp.ini
@skipline Propagation

Communication trails are enabled, which are fading blue lines on
successful physical layer communication paths:

@dontinclude omnetpp.ini
@skipline displayCommunicationTrail

@section s2results Results

This results in bubble animations representing radio
transmissions, and blue lines indicating communication paths:

<img src="step2_2_v3.gif">

<b>Number of packets received by host B: 2422</b>

Sources: @ref omnetpp.ini, @ref WirelessA.ned

@nav{step1,step3}


<!------------------------------------------------------------------------>


@page step3 Step 3 - Adding more nodes and decreasing the communication range

@nav{step2,step4}

@section s3goals Goals

Later in this tutorial, we'll want to turn our model into an ad-hoc network
and experiment with routing. To this end, in this step we add three more
wireless nodes, and reduce the communication range so that our two original
hosts cannot reach one another directly. In later steps, we'll set up
routing and use the extra nodes as relays.

@section s3model The model

In this scenario, we add 3 more hosts by extending WirelessA.ned into WirelessB.ned:

@dontinclude WirelessB.ned
@skip network
@until hostR3
@skipline }
@skipline }

We decrease the communication range of all hosts' radios to 250 meters to place hosts A and B out of
communication range.

@dontinclude omnetpp.ini
@skipline [Config Wireless03]
@until ####

@section s3results Results

Hosts A and B are placed 400 meters appart, making direct communication between
the them impossible because of the decrease in communication range of their
radios. The recently added hosts are in the correct positions to relay data between hosts
A and B, but routing is not yet configured. The result is that Host A and B
cannot communicate at all. Hosts R1 and R2 are the only hosts in communication
range of Host A, so they are the only ones that receive Host A's transmissions.
This is indicated by the blue lines connecting Host A to R1 and R2, respectively,
indicating successful receptions in the physical layer.

<img src="wireless-step3-v2.png">

<b>Number of packets received by host B: 0</b>

Sources: @ref omnetpp.ini, @ref WirelessB.ned

@nav{step2,step4}


<!------------------------------------------------------------------------>


@page step4 Step 4 - Setting up static routing

@nav{step3,step5}

@section s4goals Goals

In this step, we set up routing so that packets can flow from host A to B
and vice versa. For this to happen, the intermediate nodes will need to act
as a routers. As we still want to keep things simple, we'll use statically
added routes that remain unchanged throughout the simulation.

@section s4model The model

For the recently added hosts to act as routers, IPv4 forwarding is enabled.

It is convenient to use the 'IPv4Configurator' module to configure routing.
We want the intermediate hosts (R1-R3) to relay data from Host A to B. To keep
things simple, each host is configured to be in a separate network. This way,
routing tables contain each individual route between all hosts, making it easier
to read.

<!rewrite>We tell the configurator to assign IP addresses in the 10.0.0.x range, and to
create routes based on the estimated error rate of links between the nodes. In
the case of the <tt>IdealRadio</tt> model, the error rate is 1 for nodes that
are out of range, and 1e-3 for ones in range. The result will be that nodes that
are out of range of each other will send packets to intermediate nodes that can
forward them.<!rewrite>

Routes can be visualized as colored poliarrows (?) by the 'routeVisualizer'
submodule, which displays active routes. An active route is a route on which a packet has
been recently sent between the network layers of the two endhosts. The route becomes inactive after
a certain ammount of time unless it is reinforced by another packet. 
By specifying "*" in the packetNameFilter parameter, all types of packets
are visualized.

@dontinclude omnetpp.ini
@skipline [Config Wireless04]
@until ####

@section s4results Results

Now the two hosts can communicate as Host R1 relays data to
Host B. The arrows indicate routes in the network layer, there is a route
going from Host A through R1 to B, tracing the UDP stream.

Note that there are blue lines leading to Host R2 and R3 even though they don't
transmit. This is because they receive the transmissions at the physical layer,
but they discard the packets at the link layer because it is not addressed to
them.

The data rate is the same as before (800 kbps) -- even though multiple hosts are
 transmitting at the same time -- because interference is still ignored.

<img src="wireless-step4-v2.png">

<b>Number of packets received by host B: 2453</b>

Sources: @ref omnetpp.ini, @ref WirelessB.ned,

@nav{step3,step5}


<!------------------------------------------------------------------------>


@page step5 Step 5 - Taking interference into account

@nav{step4,step6}

@section s5goals Goals

In this step, we make our model of the physical layer a little bit more
realistic. First, we turn on interference modeling in the unit disc radio.
By interference we mean that if two signals collide (arrive at the receiver
at the same time), they will become garbled and the reception will fail.
(Remember that so far we were essentially modeling pairwise duplex
communication.)

Second, we'll set the interference range of the unit disc radio to be 500m,
twice as much as the transmission range. The interference range parameter
acknowledges the fact that radio signals become weaker with distance, and
there is a range where they can no longer be received correctly, but they
are still strong enough to interfere with other signals, that is, can cause
the reception to fail. (For completeness, there is a third range called
detection range, where signals are too weak to cause interference, but can
still be detected by the receiver.)

Of course, both changes reduce the throughput of the communication
channel, so we expect the number of packets that go through to drop.

@section s5model The model

We refine our model by enabling the simulation of interference:

@dontinclude omnetpp.ini
@skipline *.host*.wlan[*].radio.receiver.ignoreInterference = false

Set maximum interference range to the double of the communication range, 500m:

@dontinclude omnetpp.ini
@skipline *.host*.wlan[*].radio.transmitter.maxInterferenceRange = 500m

This means that Host A cannot communicate with Host B because it is out of
range, but its transmission will cause interference with other transmissions at Host B.

@dontinclude omnetpp.ini
@skipline [Config Wireless05]
@until ####

@section s5results Results

<img src="wireless-step5-v2.png">

Host A starts sending a lot of packets, at nearly the capacity of the medium.
R1 is constantly in receiving state -- nothing is controlling who can transmit
and when. R1's queue is filling up. It is supposed to relay the packets to B,
but can't as long as it is receiving A's transmissions. When A's random send
interval is a bit longer, R1 has the chance to send its queued packets to B.
Most of the time however, A starts transmitting again and its transmission
interferes with R1's at B. Packets only get through to B when the send interval
at A is greater than the time it takes for R1 to send a packet. The result is
that a very low number of packets get to B successfully. This is extemely low
throughput -- 40 packets arrive at B out of around 2500 (about 12 kbps out of
the 1 Mbps bandwidth).

@note If you lower the exponential send interval (for example, to 5ms).
In this case, A's transmission rate maxes out the radio bandwidth.
You will see that no packet arrives to B at all. The opposite happens if you
increase the interval beyond 10ms -- more packets get through to B.

What happens here is Host A starts sending packets at random intervals, and Host
R1 is supposed to relay them to Host B. However, Host R1 is almost constantly in
receiving state. R1 gets to transmit when A's random interval between
transmissions is by chance greater, but most of the time its transmission do not
make it Host B without Host A's transmissions interfering. Meanwhile, R1's send
queue is filling up, as it doesn't get the chance to transmit. The result is
that only a handful of packets make it to Host B. The throughput is minial -- 40
packets make it out of about 2500, which is about 12 kbps (out of 1 Mbps
possible bandwidth).

When you run the simulation, you will see that it's mostly Host A that is
transmitting -- Host R1 should be relaying the packets to Host B, but it can't
transmit while receiving from Host A. As Host A is generating packets in random
intervals, sometimes the interval is great enough for Host R1 to transmit a
packet. Most of the time, these packets are not delivered successfully because
Host A starts to transmit before Host R1 finished transmitting. So they are cut
by interference. Only a handful of packets arrive at Host B. <!rewrite>

To minimize interference, we need some kind of media access protocol to govern
which host can transmit and when.

<b>Number of packets received by host B: 40</b>

Sources: @ref omnetpp.ini, @ref WirelessB.ned

@nav{step4,step6}

<!------------------------------------------------------------------------>

@page step6 Step 6 - Using CSMA to better utilize the medium

@nav{step5,step7}

@section s6goals Goals

In this step, we try to increase the efficiency of the communication by
choosing a medium access (MAC) protocol that is better suited for wireless
communication.

In the previous step, nodes transmitted on the channel immediately when
they had something to send, without first listening for ongoing
transmissions, and this resulted in a lot of collisions and lost packets.
We improve the communication by using the CSMA protocol, which is based
on the "sense before transmit" (or "listen before talk") principle.

CSMA (Carrier sense multiple access) is a probabilistic MAC protocol in
which a node verifies the absence of other traffic before transmitting on
the shared transmission medium. In this protocol, a node that has data to
send first waits for the channel to become idle, and then it also waits for
random backoff period. If the channel was still idle during the backoff,
the node can actually start transmitting. Otherwise the procedure starts
over, possibly with an updated range for the backoff period.

We expect that the use of CSMA will improve throughput, as there will be
less collisions, and the medium will be utilized better.

TODO What about ACKs? Turn them on in a SEPARATE step!

@section s6model The model

We need to switch the <tt>IdealWirelessNic</tt> to <tt>WirelessNic</tt>, which can use CSMA:

@dontinclude omnetpp.ini
@skipline *.host*.wlan[*].typename = "WirelessNic"

<tt>WirelessNic</tt> has <tt>Ieee80211</tt> radio by default, but we still
want to use <tt>IdealRadio</tt>:

@dontinclude omnetpp.ini
@skipline *.host*.wlan[*].radioType = "IdealRadio"

Set mac protocol to CSMA:

@dontinclude omnetpp.ini
@skipline *.host*.wlan[*].macType = "CSMA"

We need to turn on mac acknowledgements so hosts can detect if a transmission
needs resending:

@dontinclude omnetpp.ini
@skipline *.host*.wlan[*].mac.useMACAcks = true

@dontinclude omnetpp.ini
@skipline [Config Wireless06]
@until ####

@section s6results Results

<img src="wireless-step6-v2.png">

We can see that throughput is about 380 kbps, so it is increased over the
previous step thanks to CSMA -- altough less than in step 4 because of the
interference.

<b>Number of packets received by host B: 1172</b>

Sources: @ref omnetpp.ini, @ref WirelessB.ned

@nav{step5,step7}

<!------------------------------------------------------------------------>

@page step7 Step 7 - Configuring node movements

@nav{step6,step8}

@section s7goals Goals

In this step, we make the model more interesting by adding node mobility.
Namely, we make the intermediate nodes travel north during simulation.
This will cause them to move out of the range of host A and B, breaking the
communication path.

@section s7model The model

Let's configure the intermediate nodes (R1-3) to move around. We set them to
move upwards at a speed of 12 miles per hour:

@dontinclude omnetpp.ini
@skip mobility
@until mobility.angle

@dontinclude omnetpp.ini
@skipline [Config Wireless07]
@until ####

@section s7results Results

<!more on linearmobility>
<!do we need more on mobility? should be clear from the code above>

You should run the simulation in fast mode to better see the nodes moving,
because they move very slowly if run in normal mode.

We see that data exchange works just like in the previous step until R1 moves
out of range of A. Traffic could be routed through R2 and R3, but the routing
tables are static, and configured according to the starting positions of the
nodes. Throughput is about 260 kbps, which is less than in the previous step,
because at around 18 seconds, R1 moves out of range of A thus severing the
connection to B.

<img src="step7_2_v3.gif">

A dynamic routing mechanism is needed to reconfigure the routes as nodes move out of range.

<b>Number of packets received by host B: 787</b>

Sources: @ref omnetpp.ini, @ref WirelessB.ned

@nav{step6,step8}

<!------------------------------------------------------------------------>


@page step8 Step 8 - Configuring ad-hoc routing (AODV)

@nav{step7,step9}

@section s8goals Goals

In this step, we configure a routing protocol that adapts to the changing
network topology, and will arrange packets to be routed through `R2` and `R3`
as `R1` departs.

We'll use AODV (ad hoc on-demand distance vector routing). It is a
reactive routing protocol, which means its maintenance of the routing
tables is driven by demand. This is in contrast to proactive routing
protocols which keep routing tables up to date all the time (or at least
try to).

@section s8model The model

Let's configure ad-hoc routing with AODV.

We need the <tt>IPv4NetworkConfigurator</tt> to only assign the IP addresses. We
turn all other functions off:

@dontinclude omnetpp.ini
@skip *.configurator.addStaticRoutes = false
@until Subnet

Replace <tt>INetworkNode</tt>s with <tt>AODVRouter</tt>s:

@dontinclude omnetpp.ini
@skipline *.hostType = "AODVRouter"

<tt>AODVRouter</tt> is basically an <tt>INetworkNode</tt> extended with the
<tt>AODVRouting</tt> submodule. Each node works like a router -- they manage
their own routing tables and adapt to changes in the network topology.

@dontinclude omnetpp.ini
@skipline [Config Wireless08]
@until ####

@section s8results Results

This time when R1 gets out of range, the routes are reconfigured and packets
keep flowing to B. Throughput is about the same as in step 6 -- even though the
connection is not broken here, the AODV protocol adds some overhead to the
communication.

<img src="wireless-step8-v2.png">

<b>Number of packets received by host B: 890</b>

Sources: @ref omnetpp.ini, @ref WirelessB.ned

@nav{step7,step9}

<!------------------------------------------------------------------------>

@page step9 Step 9 - Modeling energy consumption

@nav{step8,step10}

@section s9goals Goals

Wireless ad-hoc networks often operate in an energy-constrained
environment, and thus it is often useful to model the energy consumption of
the devices. Consider, for example, wireless motes that operate on battery.
The mote's activity has be planned so that the battery lasts until it can
be recharged or replaced.

In this step, we augment the nodes with components so that we can model
(and measure) their energy consumption. For simplicity, we ignore energy
constraints, and just install infinite energy sources into the nodes.

@section s9model The model

First set up energy consumption in the node radios:

@dontinclude omnetpp.ini
@skipline **.energyConsumerType = "StateBasedEnergyConsumer"

The <tt>StateBasedEnergyConsumer</tt> module models radio power consumption
based on states like radio mode, transmitter and receiver state. Each state has
a constant power consumption that can be set by a parameter. Energy use depends
on how much time the radio spends in a particular state.

Set up energy storage in the nodes -- basically modelling the batteries:

@dontinclude omnetpp.ini
@skipline *.host*.energyStorageType = "IdealEnergyStorage"

<tt>IdealEnergyStorage</tt> provides an infinite ammount of energy, can't be
fully charged or depleted. We use this because we want to concentrate on the
power consumption, not the storage.

The energyBalance variable indicates the energy consumption
(host*.energyStorage.energyBalance). You can use the residualCapacity signal
to display energy consumption over time.

@dontinclude omnetpp.ini
@skipline [Config Wireless09]
@until ####

@section s9results Results

<img src="wireless-step9-energy.png">

<b>Number of packets received by host B: 980</b>

Sources: @ref omnetpp.ini, @ref WirelessB.ned

@nav{step8,step10}

<!------------------------------------------------------------------------>

@page step10 Step 10 - Adding obstacles to the environment

@nav{step9,step11}

@section s10goals Goals

In an attempt to make our simulation both more realistic and more
interesting, we add some obstacles to the playground.

In the real world, objects like walls, trees, buildings and hills act as
obstacles to radio signal propagation. They absorb and reflect radio waves,
reducing signal quality and decreasing the chance of successful reception.

In this step, we add a concrete wall to the model that sits between host A
and `R1`, and see what happens. Since our model still uses the ideal radio
and ideal wireless medium models that do not model physical phenomena,
obstable modeling will be very simple, too: all obstacles completely absorb
radio signals that go through them, making reception behind them
impossible.

TODO jo lenne ha ez tenyleg igy mukodne!

@section s10model The model

We have to extend WirelessB.ned to include an <tt>environment</tt> module:

@dontinclude WirelessC.ned
@skip network WirelessC extends WirelessB
@until @display
@skipline }
@skipline }

The physical environment module implements the objects that interact with
transmissions -- various shapes can be created. <!rewrite>

Objects can be defined in .xml files (see details in the
<a href="https://omnetpp.org/doc/inet/api-current/inet-manual-draft.pdf" target="_blank">INET manual</a>).
Our wall is defined in walls.xml.

@dontinclude walls.xml
@skip environment
@until /environment

We need to configure the environment in omnetpp.ini:

@dontinclude omnetpp.ini
@skipline *.physicalEnvironment.config = xmldoc("walls.xml")

To calculate interactions with obstacles, we need an obstacle loss model:
@dontinclude omnetpp.ini
@skipline obstacleLoss

@dontinclude omnetpp.ini
@skipline [Config Wireless10]
@until ####


@section s10results Results

`TracingObstacleLoss` models signal loss along a line connecting the
transmitter and the receiver, calculating the loss where it intersects
obstacles. <!rewrite>

Unfortunately, the wall has no effect on the transmissions -- the number of
received packets is exactly the same as in the previous step -- because our
simple radio model doesn't interact with obstacles. We need a more realistic
radio model.

<img src="wireless-step10-v2.png">

<b>Number of packets received by host B: 603</b>

Sources: omnetpp.ini, WirelessC.ned, walls.xml

@nav{step9,step11}

<!------------------------------------------------------------------------>

@page step11 Step 11 - Changing to a more realistic radio model

@nav{step10,step12}

@section s11goals Goals

After so many steps, we let go of the ideal radio model, and introduce a
more realistic one. Our new radio will use APSK modulation, but still
without other techniques like forward error correction, interleaving or
spreading. We also want our model of the radio channel to model attenuation
and obstacle loss.

@section s11model The model

We will have to replace <tt>IdealRadio</tt> with APSKScalarRadio.

So let's switch <tt>IdealRadioMedium</tt> with <tt>APSKScalarRadioMedium</tt>:

@dontinclude omnetpp.ini
@skipline *.mediumType = "APSKScalarRadioMedium"

Set up some background noise:

@dontinclude omnetpp.ini
@skipline *.radioMedium.backgroundNoise.power = -110dBm

<tt>APSKRadioMedium</tt> uses <tt>IsotropicScalarBackgroundNoise</tt> by
default. This is basically white noise that is constant in space, time and
frequency.<!white noise already means every frequency>

<!frequency 2 ghz>

Set up <tt>APSKScalarRadio</tt>'s in the nodes and configure each radio:

@dontinclude omnetpp.ini
@skip *.host*.wlan[*].radioType = "APSKScalarRadio"
@until *.host*.wlan[*].radio.receiver.snirThreshold = 4dB

@note Each <tt>radioMedium</tt> model has to be used with the corresponding
radio model -- this case <tt>APSKScalarRadioMedium</tt> with
<tt>APSKScalarRadio</tt>. The same was true with <tt>IdealRadio</tt>.
<!do we need this - is it correct - do we need this here and not at idealradio -
last 3 lines - preambleduration?>

<!img>

@dontinclude omnetpp.ini
@skipline [Config Wireless11]
@until ####


@section s11results Results

<!results>
<!throughput>

Now our model takes the objects into account when calculating attenuation.
The wall is blocking the transmission between Host A and R1 when R1 gets
behind it.<!rewrite>

<b>Number of packets received by host B: 477</b>

Sources: @ref omnetpp.ini, @ref WirelessC.ned

@nav{step10,step12}

<!------------------------------------------------------------------------>

@page step12 Step 12 - Configuring a more accurate pathloss model

@nav{step11,step13}

@section s12goals Goals

By default, the medium uses the free space model. To make our model even
more accurate, let's configure a more realistic pathloss model, the two-ray
ground reflection model here (assuming the we are walking on the ground).

@section s12model The model

At this point we could also configure the computation model for the medium (scalar,
multidimensional) the propagation mode (constant speed, constant time) etc.
(see the radioMedium's parameters for further detail.)

@dontinclude omnetpp.ini
@skipline [Config Wireless12]
@until ####

@section s12results Results

TODO

<b>Number of packets received by host B: 243</b>

@nav{step11,step13}

<!------------------------------------------------------------------------>

@page step13 Step 13 - Enhancing the antenna with some constant gain

@nav{step12,index}

@section s13goals Goals

TODO eddig nem volt gain?

@section s13model The model

TODO

@dontinclude omnetpp.ini
@skipline [Config Wireless13]
@until ####

@section s13results Results

TODO

<b>Number of packets received by host B: 942</b>

@nav{step12,index}

*/

